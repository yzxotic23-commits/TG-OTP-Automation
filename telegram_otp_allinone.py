from __future__ import annotations

import argparse
import asyncio
import difflib
import html
import inspect
import json
import logging
import os
import re
import sqlite3
import sys
import time
import unicodedata
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from dotenv import load_dotenv
from filelock import FileLock, Timeout as FileLockTimeout
from telethon import TelegramClient, events
from telethon.tl.types import UpdateUserName
from telegram import Update
from telegram.constants import ChatType
from telegram.error import Conflict
from telegram.ext import (
    Application,
    ApplicationHandlerStop,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)


logger = logging.getLogger(__name__)


def _configure_stdio_utf8() -> None:
    """Windows console often cp1252 — avoid UnicodeEncodeError on ✓/→ in LISTEN logs."""
    if sys.platform != "win32":
        return
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def _configure_runtime_warnings() -> None:
    """Suppress google-auth (Python 3.9 EOL) and urllib3/LibreSSL warnings on macOS."""
    import warnings

    warnings.filterwarnings("ignore", category=FutureWarning, module=r"google\.auth")
    warnings.filterwarnings("ignore", category=FutureWarning, module=r"google\.oauth2")
    try:
        from urllib3.exceptions import NotOpenSSLWarning
    except ImportError:
        pass
    else:
        warnings.filterwarnings("ignore", category=NotOpenSSLWarning)


# Pola OTP (placeholder {d} = jumlah digit, di-compile per panjang kode)
_STRICT_PATTERN_TEMPLATES: tuple[str, ...] = (
    r"(?i)login\s*code\s*(?:is\s*)?[:\s]*(\d{{{d}}})\b",
    r"(?i)code\s*for\s*logging\s*in[^0-9]{{0,40}}(\d{{{d}}})\b",
    r"(?i)this\s+is\s+your\s+login\s+code[^0-9]{{0,20}}(\d{{{d}}})\b",
    r"(?i)код[^0-9]{{0,25}}(\d{{{d}}})\b",
    r"(?i)verification\s*code[^0-9]{{0,20}}(\d{{{d}}})\b",
    r"(?i)(?:sign[-\s]?in|signin)\s*code[^0-9]{{0,25}}(\d{{{d}}})\b",
    r"(?i)telegram[^0-9]{{0,40}}(\d{{{d}}})\b",
    r"(?i)(?:kode\s*masuk|kode\s*login)[^0-9]{{0,25}}(\d{{{d}}})\b",
    r"(?i)c[oó]digo[^0-9]{{0,30}}(\d{{{d}}})\b",
    r"(?i)(?:best[aä]tigungscode|sicherheitscode)[^0-9]{{0,25}}(\d{{{d}}})\b",
    r"(?i)(?:one[-\s]?time|one\s*time)\s*(?:password|code)[^0-9]{{0,25}}(\d{{{d}}})\b",
    r"(?i)(?:your|the)\s+code[^0-9]{{0,30}}(\d{{{d}}})\b",
)

# Proximity: code near keywords (smart detection without full loose mode)
_SMART_PROXIMITY_TMPL = (
    r"(?is)(?:login|sign[-\s]?in|telegram|verification|kode\s*(?:masuk|login)|code|c[oó]digo)"
    r".{{0,120}}?(\d{{{d}}})\b"
)

# Alias kunci template multiline -> canonical (account_name / account_number)
_TEMPLATE_KEY_ALIASES: dict[str, frozenset[str]] = {
    "account_name": frozenset(
        {
            "account_name",
            "nama",
            "nama_akun",
            "name",
            "username",
            "user_name",
            "id_akun",
            "account",
            "profile",
            "user",
        }
    ),
    "account_number": frozenset(
        {
            "account_number",
            "account_no",
            "no_akun",
            "rekening",
            "nomor_rekening",
            "no_rekening",
            "phone",
            "nomor_hp",
            "no_hp",
            "hp",
            "whatsapp",
            "wa",
            "mobile",
            "tel",
            "telepon",
        }
    ),
}

_STRICT_COMPILED_CACHE: dict[int, tuple[re.Pattern[str], ...]] = {}


def _compiled_strict_for_length(n: int) -> tuple[re.Pattern[str], ...]:
    if n not in _STRICT_COMPILED_CACHE:
        strict = tuple(re.compile(t.format(d=n)) for t in _STRICT_PATTERN_TEMPLATES)
        _STRICT_COMPILED_CACHE[n] = strict
    return _STRICT_COMPILED_CACHE[n]


def otp_code_lengths() -> list[int]:
    raw = (os.environ.get("TELEGRAM_OTP_CODE_LENGTHS") or "5").strip()
    out: list[int] = []
    for part in raw.replace(" ", "").split(","):
        if not part:
            continue
        try:
            n = int(part)
            if 4 <= n <= 8:
                out.append(n)
        except ValueError:
            continue
    return sorted(set(out or [5]))


def _env_int(name: str, default: int, *, minimum: int = 0) -> int:
    try:
        v = int(str(os.environ.get(name, "")).strip() or default)
        return max(minimum, v)
    except ValueError:
        return default


def _json_lock(path: Path) -> FileLock:
    lockfile = path.parent / (path.name + ".lock")
    timeout = _env_int("TELEGRAM_JSON_LOCK_TIMEOUT_SEC", 20, minimum=1)
    return FileLock(str(lockfile), timeout=timeout)


def _mutate_json_file(path: Path, writer: Callable[[dict[str, Any]], None]) -> bool:
    """Atomic read-modify-write with cross-process lock. False on timeout / corrupt data."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with _json_lock(path):
            data, ok = read_json_for_mutation(path)
            if not ok:
                return False
            writer(data)
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            tmp.replace(path)
    except FileLockTimeout:
        logger.error("JSON file lock timeout (another process holding it?): %s", path)
        return False
    except OSError as e:
        logger.error("Failed to write JSON %s: %s", path, e)
        return False
    return True


def normalize_message_for_otp(text: str) -> str:
    """NFKC + buang zero-width agar pola regex stabil."""
    if not text:
        return ""
    s = unicodedata.normalize("NFKC", text)
    s = re.sub(r"[\u200b-\u200d\ufeff\u2060]", "", s)
    return s


def extract_login_code(text: str, loose: bool) -> str | None:
    norm = normalize_message_for_otp(text or "")
    if not norm.strip():
        return None
    lengths = otp_code_lengths()
    for n in lengths:
        for pat in _compiled_strict_for_length(n):
            m = pat.search(norm)
            if m:
                return m.group(1)
    smart = os.environ.get("TELEGRAM_OTP_SMART_DETECT", "1").strip().lower() not in (
        "0",
        "false",
        "no",
        "off",
    )
    if smart:
        for n in lengths:
            prox = re.compile(_SMART_PROXIMITY_TMPL.format(d=n))
            m = prox.search(norm)
            if m:
                return m.group(1)
    if loose:
        for n in lengths:
            candidates = list(re.finditer(rf"\b(\d{{{n}}})\b", norm))
            if len(candidates) == 1:
                return candidates[0].group(1)
            if len(candidates) > 1:
                # avoid years 20xx / 19xx as OTP
                filtered = [c for c in candidates if not re.match(r"^(?:19|20)\d{2}$", c.group(1))]
                if len(filtered) == 1:
                    return filtered[0].group(1)
    return None


LOGIN_REQ_PATTERN = re.compile(r"(?i)^\s*(?:login|req|request)\s+@?([a-z0-9_.\-]+)\s*$")

# Dedupe OTP per account (in-process); mark only after successful send
_last_otp_sent: dict[str, tuple[str, float]] = {}


def is_recent_otp_duplicate(account_id: str, code: str) -> bool:
    window = _env_int("TELEGRAM_OTP_DEDUP_SEC", 25, minimum=0)
    if window <= 0:
        return False
    now = time.time()
    key = f"{account_id}:{code}"
    prev = _last_otp_sent.get(key)
    if prev and (now - prev[1]) < window:
        return True
    return False


def record_otp_sent(account_id: str, code: str) -> None:
    window = _env_int("TELEGRAM_OTP_DEDUP_SEC", 25, minimum=0)
    if window <= 0:
        return
    now = time.time()
    key = f"{account_id}:{code}"
    _last_otp_sent[key] = (code, now)
    if len(_last_otp_sent) > 500:
        cutoff = now - max(window * 4, 120.0)
        dead = [k for k, (_, t) in _last_otp_sent.items() if t < cutoff]
        for k in dead:
            del _last_otp_sent[k]


def project_root() -> Path:
    return Path(__file__).resolve().parent


def accounts_json_path(override: str | None = None) -> Path:
    root = project_root()
    o = (override or "").strip() or os.environ.get("TELEGRAM_ACCOUNTS_FILE", "").strip()
    if o:
        p = Path(o)
        return p if p.is_absolute() else (root / p).resolve()
    for name in ("accounts.json", "account.json"):
        candidate = root / name
        if candidate.is_file():
            return candidate
    return root / "accounts.json"


def shooter_accounts_json_path() -> Path:
    root = project_root()
    o = os.environ.get("TELEGRAM_SHOOTER_ACCOUNTS_FILE", "").strip()
    if o:
        p = Path(o)
        return p if p.is_absolute() else (root / p).resolve()
    candidate = root / "shooteraccounts.json"
    return candidate


def load_shooter_doc() -> dict[str, Any]:
    return load_json(shooter_accounts_json_path())


def state_json_path() -> Path:
    return project_root() / "state.json"


def load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        logger.warning("load_json cannot read %s: %s", path, e)
        return {}
    if not text.strip():
        return {}
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as e:
        logger.error("load_json invalid JSON %s: %s", path, e)
        return {}
    return raw if isinstance(raw, dict) else {}


def read_json_for_mutation(path: Path) -> tuple[dict[str, Any], bool]:
    """Read JSON for read-modify-write. (data, True) OK; (_, False) do not write (corrupt/OS error)."""
    if not path.is_file():
        return {}, True
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        logger.error("Cannot read %s: %s", path, e)
        return {}, False
    if not text.strip():
        return {}, True
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as e:
        logger.error("Corrupt JSON, skip write to avoid data loss: %s: %s", path, e)
        return {}, False
    if not isinstance(raw, dict):
        logger.error("Not a JSON object in %s, skip write.", path)
        return {}, False
    return raw, True


def write_last_private_chat(path: Path, chat_id: str, account_hint: str) -> None:
    def writer(data: dict[str, Any]) -> None:
        data["last_chat_id"] = str(chat_id)
        data["last_account_id"] = account_hint
        data["updated_at"] = datetime.now(timezone.utc).isoformat()

    if not _mutate_json_file(path, writer):
        logger.warning("write_last_private_chat failed: %s", path)


def read_last_chat_id(path: Path) -> str | None:
    try:
        with _json_lock(path):
            if not path.is_file():
                return None
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                return None
            v = data.get("last_chat_id")
            return str(v).strip() if v else None
    except FileLockTimeout:
        logger.warning("Timeout lock read_last_chat_id: %s", path)
        return None


def upsert_account(
    path: Path,
    account_id: str,
    chat_id: str,
    label: str,
    telegram_user_id: str | None = None,
) -> None:
    def writer(data: dict[str, Any]) -> None:
        rows = data.get("accounts")
        if not isinstance(rows, list):
            rows = []
        found = False
        for row in rows:
            if not isinstance(row, dict):
                continue
            if str(row.get("id", "")).strip() == account_id:
                row["chat_id"] = str(chat_id)
                row["label"] = label
                if telegram_user_id:
                    row["telegram_user_id"] = str(telegram_user_id)
                found = True
                break
        if not found:
            entry: dict[str, Any] = {
                "id": account_id,
                "chat_id": str(chat_id),
                "label": label,
            }
            if telegram_user_id:
                entry["telegram_user_id"] = str(telegram_user_id)
            rows.append(entry)
        data["accounts"] = rows
        if not data.get("default_account"):
            data["default_account"] = account_id

    if not _mutate_json_file(path, writer):
        logger.warning("upsert_account failed: %s", path)


def _staff_row_should_preserve_label(row: dict[str, Any]) -> bool:
    """Do not overwrite admin label — used to map shooter owner (VENAN, KAREN, …)."""
    if str(row.get("shooter_owner") or "").strip():
        return True
    owners = get_configured_shooter_owners()
    if not owners:
        return False
    label = str(row.get("label") or "").strip()
    if not label:
        return False
    for part in label.replace("_", " ").split():
        if part.strip().upper() in owners:
            return True
    return label.strip().upper() in owners


def infer_shooter_owner_from_staff_row(row: dict[str, Any], staff_id: str = "") -> str:
    """Detect shooter owner (VENAN, RINTO, …) from staff row in accounts.json."""
    owners = get_configured_shooter_owners()
    if not owners:
        return ""
    explicit = str(row.get("shooter_owner") or "").strip().upper()
    if explicit:
        return explicit
    candidates: list[str] = [staff_id, str(row.get("id") or ""), str(row.get("label") or "")]
    candidates.extend(_row_telegram_usernames(row))
    for raw in candidates:
        text = str(raw or "").strip()
        if not text:
            continue
        whole = text.upper()
        if whole in owners:
            return whole
        for part in text.replace("_", " ").split():
            token = part.strip().upper()
            if token in owners:
                return token
    return ""


def _apply_staff_telegram_fields(row: dict[str, Any], user: Any, chat_id: str | None, label: str) -> None:
    """Save Telegram profile (id/username); admin label kept if shooter mapping exists."""
    existing = str(row.get("label") or "").strip()
    if label and not existing:
        row["label"] = label
    elif label and not _staff_row_should_preserve_label(row):
        row["label"] = label
    if chat_id is not None:
        row["chat_id"] = str(chat_id).strip()
    tg_id = str(getattr(user, "id", "") or "").strip()
    if tg_id:
        row["telegram_user_id"] = tg_id
    un = (getattr(user, "username", None) or "").strip().lstrip("@")
    if un:
        row["telegram_username"] = un
    inferred = infer_shooter_owner_from_staff_row(row, str(row.get("id") or ""))
    if inferred and not str(row.get("shooter_owner") or "").strip():
        row["shooter_owner"] = inferred


def sync_staff_telegram_profile(user: Any, staff_id: str) -> None:
    """Update telegram_user_id / @username only — shooter admin label unchanged."""
    if not user or not staff_id or staff_id == "__creator__":
        return
    tg_id = str(getattr(user, "id", "") or "").strip()
    if not tg_id:
        return
    path = accounts_json_path()
    key = staff_id.strip().lower()

    def writer(data: dict[str, Any]) -> None:
        rows = data.get("accounts")
        if not isinstance(rows, list):
            return
        for row in rows:
            if not isinstance(row, dict):
                continue
            if str(row.get("id", "")).strip().lower() != key:
                continue
            _apply_staff_telegram_fields(row, user, None, "")
            return

    if not _mutate_json_file(path, writer):
        logger.warning("sync_staff_telegram_profile failed: %s", staff_id)


def staff_require_allowlist() -> bool:
    """Only staff already in accounts.json may register via /start in DM."""
    return os.environ.get("TELEGRAM_STAFF_REQUIRE_ALLOWLIST", "1").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def _register_match_staff_row(row: dict[str, Any], user: Any, chat_id: str, label: str) -> str:
    _apply_staff_telegram_fields(row, user, chat_id, label)
    return str(row.get("id", "")).strip()


def _staff_row_is_unclaimed(row: dict[str, Any], tg_id: str) -> bool:
    """Slot allowlist belum terikat ke user Telegram lain."""
    existing = str(row.get("telegram_user_id") or "").strip()
    if not existing:
        return True
    return bool(tg_id and existing == tg_id)


def _staff_row_matches_user_identity(
    row: dict[str, Any],
    *,
    full_name: str,
    uname: str,
    uname_id: str,
) -> bool:
    """Match allowlist row by display name / shooter_owner / @username."""
    label = str(row.get("label") or "").strip().lower()
    full = full_name.strip().lower()
    if label and full:
        if full == label or full.startswith(label + " ") or label in full.split():
            return True
    so = str(row.get("shooter_owner") or "").strip().upper()
    if so:
        so_l = so.lower()
        if full and (so_l in full.split() or full.startswith(so_l + " ") or so_l in full):
            return True
        if uname and uname == so_l:
            return True
        if uname_id.strip().lower() == so_l:
            return True
    aid = str(row.get("id") or "").strip().lower()
    if aid:
        if uname and uname == aid:
            return True
        if uname_id.strip().lower() == aid:
            return True
        if full and aid in full.split():
            return True
    return False


def register_private_staff_chat(
    user: Any, chat_id: str, label: str, name_hint: str = ""
) -> tuple[str, bool]:
    """
    Daftar / update staff di accounts.json.
    Priority: telegram_user_id → @username → name_hint (from /start <name>) → full_name → staff id → chat_id.
    Return (staff_id, linked) — linked=False if not in allowlist.
    """
    path = accounts_json_path()
    tg_id = str(getattr(user, "id", "") or "").strip()
    uname_id = account_id_from_user(user)
    uname = (getattr(user, "username", None) or "").strip().lower().lstrip("@")
    full_name = (getattr(user, "full_name", None) or label or "").strip()
    hint = name_hint.strip().upper()
    resolved_id = uname_id
    linked = False

    def writer(data: dict[str, Any]) -> None:
        nonlocal resolved_id, linked
        rows = data.get("accounts")
        if not isinstance(rows, list):
            rows = []
        if tg_id:
            for row in rows:
                if not isinstance(row, dict):
                    continue
                aid = str(row.get("id", "")).strip().lower()
                if not aid or aid == creator_account_id():
                    continue
                if str(row.get("telegram_user_id", "")).strip() == tg_id:
                    resolved_id = _register_match_staff_row(row, user, chat_id, label)
                    linked = True
                    data["accounts"] = rows
                    return
        if uname:
            for row in rows:
                if not isinstance(row, dict):
                    continue
                aid = str(row.get("id", "")).strip().lower()
                if not aid or aid == creator_account_id():
                    continue
                if uname == aid or uname in _row_telegram_usernames(row):
                    resolved_id = _register_match_staff_row(row, user, chat_id, label)
                    linked = True
                    data["accounts"] = rows
                    return
        for row in rows:
            if not isinstance(row, dict):
                continue
            if str(row.get("id", "")).strip().lower() == uname_id.strip().lower():
                resolved_id = _register_match_staff_row(row, user, chat_id, label)
                linked = True
                data["accounts"] = rows
                return
        # name_hint: /start <nama> — cocokkan shooter_owner / label / id
        if hint:
            for row in rows:
                if not isinstance(row, dict):
                    continue
                aid = str(row.get("id", "")).strip().lower()
                if not aid or aid == creator_account_id():
                    continue
                if not _staff_row_is_unclaimed(row, tg_id):
                    continue
                so = str(row.get("shooter_owner") or "").strip().upper()
                lbl = str(row.get("label") or "").strip().upper()
                if hint in (so, lbl, aid.upper()):
                    resolved_id = _register_match_staff_row(row, user, chat_id, label)
                    linked = True
                    data["accounts"] = rows
                    return
        if full_name:
            for row in rows:
                if not isinstance(row, dict):
                    continue
                aid = str(row.get("id", "")).strip().lower()
                if not aid or aid == creator_account_id():
                    continue
                if not _staff_row_is_unclaimed(row, tg_id):
                    continue
                stored_chat = str(row.get("chat_id") or "").strip()
                if stored_chat and stored_chat != str(chat_id).strip():
                    continue
                if _staff_row_matches_user_identity(
                    row, full_name=full_name, uname=uname, uname_id=uname_id
                ):
                    resolved_id = _register_match_staff_row(row, user, chat_id, label)
                    linked = True
                    data["accounts"] = rows
                    return
        for row in rows:
            if not isinstance(row, dict):
                continue
            aid = str(row.get("id", "")).strip().lower()
            if not aid or aid == creator_account_id():
                continue
            stored_chat = str(row.get("chat_id", "")).strip()
            if stored_chat and stored_chat == str(chat_id).strip():
                resolved_id = _register_match_staff_row(row, user, chat_id, label)
                linked = True
                data["accounts"] = rows
                return
        if staff_require_allowlist():
            return
        entry: dict[str, Any] = {"id": uname_id, "chat_id": str(chat_id), "label": label}
        _apply_staff_telegram_fields(entry, user, chat_id, label)
        rows.append(entry)
        data["accounts"] = rows
        linked = True

    if not _mutate_json_file(path, writer):
        logger.warning("register_private_staff_chat failed: %s", path)
    return resolved_id, linked


def _row_telegram_usernames(row: dict[str, Any]) -> set[str]:
    """All Telegram usernames recognized for this staff row."""
    names: set[str] = set()
    for key in ("telegram_username", "username"):
        v = str(row.get(key) or "").strip().lower().lstrip("@")
        if v:
            names.add(v)
    extra = row.get("telegram_usernames")
    if isinstance(extra, list):
        for item in extra:
            s = str(item or "").strip().lower().lstrip("@")
            if s:
                names.add(s)
    return names


def find_staff_rows_for_user(user: Any) -> list[dict[str, Any]]:
    """All staff rows for this Telegram user (supports shared telegram_user_id)."""
    if not user:
        return []
    tg_id = str(getattr(user, "id", "") or "").strip()
    uname = (getattr(user, "username", None) or "").strip().lower().lstrip("@")
    try:
        doc = load_json(accounts_json_path())
    except Exception:
        return []
    rows = doc.get("accounts")
    if not isinstance(rows, list):
        return []
    matched: list[dict[str, Any]] = []
    seen: set[str] = set()

    def _add(row: dict[str, Any]) -> None:
        aid = str(row.get("id", "")).strip().lower()
        if not aid or aid == creator_account_id() or aid in seen:
            return
        seen.add(aid)
        matched.append(row)

    if tg_id:
        for row in rows:
            if not isinstance(row, dict):
                continue
            if str(row.get("telegram_user_id", "")).strip() == tg_id:
                _add(row)
        for row in rows:
            if not isinstance(row, dict):
                continue
            stored_chat = str(row.get("chat_id", "")).strip()
            if stored_chat and stored_chat == tg_id:
                _add(row)
    if uname:
        for row in rows:
            if not isinstance(row, dict):
                continue
            aid = str(row.get("id", "")).strip().lower()
            if not aid or aid == creator_account_id():
                continue
            if uname == aid or uname in _row_telegram_usernames(row):
                _add(row)
    full_name = (getattr(user, "full_name", None) or "").strip()
    uname_id = account_id_from_user(user)
    if full_name:
        for row in rows:
            if not isinstance(row, dict):
                continue
            aid = str(row.get("id", "")).strip().lower()
            if not aid or aid == creator_account_id():
                continue
            if not _staff_row_is_unclaimed(row, tg_id):
                continue
            if _staff_row_matches_user_identity(
                row, full_name=full_name, uname=uname, uname_id=uname_id
            ):
                _add(row)
    return matched


def find_staff_row_for_user(
    user: Any,
    *,
    shooter_owner_hint: str = "",
) -> dict[str, Any] | None:
    """Staff row in accounts.json for this Telegram user, or None."""
    matched = find_staff_rows_for_user(user)
    if not matched:
        return None
    hint = shooter_owner_hint.strip().upper()
    if hint:
        for row in matched:
            so = str(row.get("shooter_owner") or "").strip().upper()
            aid = str(row.get("id") or "").strip().upper()
            lbl = str(row.get("label") or "").strip().upper()
            if hint in (so, aid, lbl):
                return row
            if staff_matches_shooter_owner(str(row.get("id") or ""), hint, staff_row=row):
                return row
    return matched[0]


def user_may_access_shooter_owner(user: Any, owner: str) -> bool:
    target = str(owner or "").strip().upper()
    if not target:
        return False
    if is_creator_user(user):
        return True
    for row in find_staff_rows_for_user(user):
        if staff_matches_shooter_owner(str(row.get("id") or ""), target, staff_row=row):
            return True
    return False


def ensure_staff_linked(user: Any) -> bool:
    """
    Auto-register: if user already in accounts.json (chat_id / @username / id),
    save telegram_user_id — no /start in DM required.
    """
    if not user or is_creator_user(user):
        return False
    row = find_staff_row_for_user(user)
    if not row:
        return False
    aid = str(row.get("id", "")).strip().lower()
    if not aid or aid == creator_account_id():
        return False
    label = (getattr(user, "full_name", None) or aid).strip()
    tg_id = str(getattr(user, "id", "") or "").strip()
    chat_id = tg_id or str(row.get("chat_id", "")).strip()

    def writer(data: dict[str, Any]) -> None:
        rows = data.get("accounts")
        if not isinstance(rows, list):
            return
        for r in rows:
            if isinstance(r, dict) and str(r.get("id", "")).strip().lower() == aid:
                _apply_staff_telegram_fields(r, user, chat_id, label)
                return

    path = accounts_json_path()
    if not _mutate_json_file(path, writer):
        logger.warning("ensure_staff_linked failed: %s", aid)
        return False
    return True


def resolve_requester_staff(user: Any) -> str | None:
    """
    Staff id from accounts.json (karen/widya/rizkyr) or None. Creator → __creator__.
    Prioritas: telegram_user_id (tetap walau @username ganti) → chat_id → @username.
    """
    if is_creator_user(user):
        return "__creator__"
    ensure_staff_linked(user)
    row = find_staff_row_for_user(user)
    if not row:
        return None
    aid = str(row.get("id", "")).strip().lower()
    if aid:
        sync_staff_telegram_profile(user, aid)
    return aid or None


def effective_shooter_owner_filter(
    staff: str | None,
    staff_row: dict[str, Any] | None,
    staff_shooter: str,
    owner_filter: str,
    *,
    user: Any | None = None,
) -> str:
    """Staff: typo owner → use own shooter owner (not Access Denied)."""
    key = str(owner_filter or "").strip().upper()
    if not key or staff == "__creator__":
        return key
    if user and user_may_access_shooter_owner(user, key):
        return key
    if not staff or not staff_shooter:
        return key
    if staff_matches_shooter_owner(staff, key, staff_row=staff_row):
        return key
    return staff_shooter.strip().upper()


def get_configured_shooter_owners() -> set[str]:
    """Shooter owner name (RINTO, KAREN, …) from shooteraccounts.json."""
    try:
        doc = load_shooter_doc()
        rows = load_shooter_accounts(doc)
        return set(list_shooter_owners(doc, rows))
    except Exception:
        return set()


def resolve_shooter_owner_for_staff(staff_id: str | None, row: dict[str, Any] | None = None) -> str:
    """
    Shooter owner for staff (may differ from accounts.json id, e.g. begundal6 → RINTO).
    """
    if not staff_id or staff_id == "__creator__":
        return ""
    if row is None:
        try:
            doc = load_json(accounts_json_path())
            for r in doc.get("accounts", []):
                if isinstance(r, dict) and str(r.get("id", "")).strip().lower() == staff_id.strip().lower():
                    row = r
                    break
        except Exception:
            row = None
    if isinstance(row, dict):
        inferred = infer_shooter_owner_from_staff_row(row, staff_id)
        if inferred:
            return inferred
    key = staff_id.strip().upper()
    owners = get_configured_shooter_owners()
    if key in owners:
        return key
    return key


def build_staff_not_registered_html(user: Any, *, topic_currency: str | None = None) -> str:
    who = ""
    if user:
        un = (getattr(user, "username", None) or "").strip()
        uid = str(getattr(user, "id", "") or "").strip()
        if un or uid:
            who = (
                f"\n\n<i>Your Telegram:</i> "
                + (f"@{html.escape(un)} " if un else "")
                + (f"Telegram user ID: {html.escape(uid)}" if uid else "")
            )
    return (
        accounts_header_html("⛔ <b>Not Registered</b>")
        + "\n\n"
        + "Ask your admin to add your Telegram to the <b>staff list</b>.\n"
        + group_channel_topic_hint(topic_currency=topic_currency)
        + "\nIf you are already on the list, open the matching group topic — linking is automatic "
        + "(no <code>/start</code> required there)."
        + who
    )


def build_staff_not_allowlisted_html(user: Any | None = None) -> str:
    who = ""
    if user:
        un = (getattr(user, "username", None) or "").strip()
        uid = str(getattr(user, "id", "") or "").strip()
        fn = (getattr(user, "full_name", None) or "").strip()
        parts = []
        if fn:
            parts.append(html.escape(fn))
        if un:
            parts.append(f"@{html.escape(un)}")
        if uid:
            parts.append(f"Telegram user ID: {html.escape(uid)}")
        if parts:
            who = "\n\n<i>Your Telegram:</i> " + " · ".join(parts)
    return (
        accounts_header_html("⛔ <b>Not Authorized</b>")
        + "\n\n"
        + "Your Telegram does not match any entry in the staff list.\n"
        + "Send the info below to the bot admin, then try <code>/start YourShooterName</code> again."
        + who
    )


def staff_matches_shooter_owner(
    staff_id: str | None,
    owner: str,
    *,
    staff_row: dict[str, Any] | None = None,
) -> bool:
    if staff_id == "__creator__":
        return True
    if not staff_id:
        return False
    target = str(owner or "").strip().upper()
    if not target:
        return False
    staff_owner = resolve_shooter_owner_for_staff(staff_id, staff_row)
    if staff_owner == target:
        return True
    if staff_id.strip().upper() == target:
        return True
    if isinstance(staff_row, dict):
        if str(staff_row.get("shooter_owner") or "").strip().upper() == target:
            return True
        label = str(staff_row.get("label") or "").strip().upper()
        if label == target or label.startswith(target + " "):
            return True
    return False


def build_staff_access_denied_html(
    requester_label: str,
    target_owner: str,
    *,
    for_login: bool = False,
) -> str:
    own = html.escape(requester_label)
    if for_login:
        return (
            accounts_header_html("⛔ <b>Access Denied</b>")
            + "\n\n"
            + "Cannot request OTP for another user's shooter account.\n"
            + f"Please use your own account only.\n\n"
            + f"<i>Example:</i> <code>/login SH_{own.upper()}_01</code>"
        )
    return (
        accounts_header_html("⛔ <b>Access Denied</b>")
        + "\n\n"
        + "Cannot show other shooter accounts.\n"
        + "Please re-command with your own account list.\n\n"
        + f"<i>Example:</i> <code>/other {own.upper()}</code>"
    )


def validate_shooter_owner_access(update: Update, owner: str) -> str | None:
    """Return HTML error if user may not access this shooter owner (login / someone else's account)."""
    user = update.effective_user
    ensure_staff_linked(user)
    owner_u = str(owner or "").strip().upper()
    if not owner_u:
        return accounts_header_html("⚠️ <b>Error</b>") + "\n\nInvalid owner."
    if user_may_access_shooter_owner(user, owner_u):
        return None
    staff_row = find_staff_row_for_user(user, shooter_owner_hint=owner_u)
    staff = str(staff_row.get("id") or "").strip().lower() if staff_row else resolve_requester_staff(user)
    if staff is None:
        return build_staff_not_registered_html(user)
    own_key = resolve_shooter_owner_for_staff(staff, staff_row)
    label = _format_shooter_owner_label(own_key or staff)
    return build_staff_access_denied_html(label, _format_shooter_owner_label(owner_u))


def _copy_button_label(emoji: str, value: str, max_len: int = 22) -> str:
    """Label tombol sejajar — pendek & seimbang (max 64 char di API Telegram)."""
    label = f"{emoji} {value}"
    if len(label) <= max_len:
        return label
    keep = max_len - len(emoji) - 2
    return f"{emoji} {value[:keep]}…" if keep > 0 else emoji[:max_len]


def build_otp_inline_keyboard(code: str, password: str | None) -> dict[str, Any]:
    """Tombol inline sejajar (satu baris); ketuk = salin ke clipboard (Telegram copy_text)."""
    row: list[dict[str, Any]] = [
        {"text": _copy_button_label("🔑", code), "copy_text": {"text": code}},
    ]
    if password:
        row.append(
            {
                "text": _copy_button_label("2FA :", password, max_len=28),
                "copy_text": {"text": password},
            }
        )
    return {"inline_keyboard": [row]}


def _unescape_telegram_html(tpl: str) -> str:
    return (
        html.escape(tpl)
        .replace("&lt;b&gt;", "<b>")
        .replace("&lt;/b&gt;", "</b>")
        .replace("&lt;i&gt;", "<i>")
        .replace("&lt;/i&gt;", "</i>")
        .replace("&lt;blockquote&gt;", "<blockquote>")
        .replace("&lt;/blockquote&gt;", "</blockquote>")
        .replace("&lt;code&gt;", "<code>")
        .replace("&lt;/code&gt;", "</code>")
    )


def accounts_header_html(title_line: str) -> str:
    """Kartu judul + garis (selaras dengan OTP ALERT)."""
    return f"<blockquote>{title_line}\n━━━━━━━━━━━━━━━━━━</blockquote>"


def build_accounts_overview_html(
    total: int,
    total_brands: int,
    by_currency: dict[str, list[tuple[str, list[dict[str, Any]]]]],
) -> str:
    lines: list[str] = [
        accounts_header_html("🔐 <b>OTP Accounts Overview</b>"),
        "",
        f"📊 <b>{total}</b> accounts  ·  <b>{total_brands}</b> brands",
    ]
    for currency in sorted(by_currency.keys()):
        brands_in = sorted(by_currency[currency], key=lambda x: x[0].lower())
        currency_total = sum(len(rs) for _, rs in brands_in)
        brand_count = len(brands_in)
        lines.append("")
        lines.append(
            f"💱 <b>{html.escape(currency)}</b>  ·  {currency_total} accts  ·  {brand_count} brands"
        )
        for brand, rs in brands_in:
            lines.append(f"   ◦ {html.escape(brand)}  ·  {len(rs)}")
    lines.append("")
    lines.append("<i>/main &lt;BRAND&gt;</i>  ·  <code>/main STMY</code>")
    return "\n".join(lines)


def build_accounts_currency_topic_html(
    currency: str,
    matching: list[tuple[str, list[dict[str, Any]]]],
) -> str:
    total_accs = sum(len(rs) for _, rs in matching)
    brand_count = len(matching)
    lines: list[str] = [
        accounts_header_html(f"💱 <b>{html.escape(currency)} GCS</b>"),
        "",
        f"📊 <b>{total_accs}</b> accounts  ·  <b>{brand_count}</b> brands",
        "",
    ]
    for brand, rs in sorted(matching, key=lambda x: x[0].lower()):
        lines.append(f"◦ {html.escape(brand)}  ·  {len(rs)}")
    return "\n".join(lines)


def build_accounts_brand_detail_html(
    brand: str,
    currency: str,
    rows: list[dict[str, Any]],
) -> str:
    lines: list[str] = [
        accounts_header_html(f"🔹 <b>{html.escape(brand)}</b>  ·  {html.escape(currency)}"),
        "",
    ]
    for i, r in enumerate(rows, 1):
        phone = html.escape(str(r.get("phone") or "-").strip())
        name = html.escape(str(r.get("profile_hint") or r.get("id") or "-").strip())
        lines.append(f"<b>{i}.</b> <code>{phone}</code>  ·  {name}")
    return "\n".join(lines)


def _format_shooter_owner_label(owner: str) -> str:
    o = owner.strip()
    if not o:
        return o
    return o[0].upper() + o[1:].lower()


def build_shooter_owners_list_html(shooter_rows: list[dict[str, Any]], currency: str = "MYR") -> str:
    """Ringkasan /other tanpa argumen — format selaras dengan /main GCS."""
    counts: dict[str, int] = {}
    for row in shooter_rows:
        owner = str(row.get("owner") or "").strip().upper()
        if owner:
            counts[owner] = counts.get(owner, 0) + 1
    total = sum(counts.values())
    lines: list[str] = [
        accounts_header_html(f"💱 <b>{html.escape(currency)} Shooter Account List</b>"),
        "",
        f"📊 <b>{total}</b> accounts  ·  <b>{len(counts)}</b> users",
        "",
    ]
    if not counts:
        lines.append("<i>No shooter accounts yet.</i>")
        return "\n".join(lines)
    for owner in sorted(counts.keys(), key=lambda x: x.lower()):
        n = counts[owner]
        label = _format_shooter_owner_label(owner)
        lines.append(f"◦ <b>{html.escape(label)}</b>  ·  {n}")
    lines.append("")
    lines.append("<i>/other &lt;USER&gt;</i>  ·  <code>/other KAREN</code>")
    return "\n".join(lines)


def build_shooter_user_accounts_html(
    owner: str,
    rows: list[dict[str, Any]],
    brands_cfg: dict[str, dict[str, Any]],
) -> str:
    rows_sorted = sorted(rows, key=lambda r: (str(r.get("phone") or "")).lower())
    lines: list[str] = [
        accounts_header_html(f"🎯 <b>Shooter · {html.escape(owner)}</b>"),
    ]
    idx = 0
    if shooter_rows_have_brand(rows_sorted):
        grouped = group_shooter_rows_by_brand(rows_sorted)
        unbranded = [r for r in rows_sorted if not shooter_row_has_brand(r)]
        for brand, brand_rows in grouped.items():
            currency = derive_brand_currency(brand, brands_cfg)
            lines.append("")
            lines.append(f"🔹 <b>{html.escape(brand)}</b>  ·  {html.escape(currency)}")
            lines.append("")
            for r in brand_rows:
                idx += 1
                lines.append(format_shooter_account_line(r, idx))
        if unbranded:
            lines.append("")
            lines.append("◦ <b>Shooter accounts</b>")
            lines.append("")
            for r in unbranded:
                idx += 1
                lines.append(format_shooter_account_line(r, idx))
    else:
        lines.append("")
        for r in rows_sorted:
            idx += 1
            lines.append(format_shooter_account_line(r, idx))
    lines.append("")
    lines.append("<i>GCS list:</i> <code>/main</code>")
    return "\n".join(lines)


def build_shooter_user_not_found_html(owner: str, known: list[str]) -> str:
    preview = ", ".join(f"<code>{html.escape(o)}</code>" for o in known[:16])
    more = f" … +{len(known) - 16}" if len(known) > 16 else ""
    return (
        accounts_header_html("⚠️ <b>Shooter User Not Found</b>")
        + f"\n\nNo shooter accounts for <code>{html.escape(owner)}</code>.\n\n"
        + (f"<b>Users:</b> {preview}{more}\n\n" if known else "No shooter users configured.\n\n")
        + "<i>Example:</i> <code>/other GERI</code>"
    )


def build_accounts_brand_not_found_html(brand_filter: str, known: list[str]) -> str:
    preview = ", ".join(html.escape(b) for b in sorted(known, key=str.lower)[:12])
    more = f" … +{len(known) - 12}" if len(known) > 12 else ""
    return (
        accounts_header_html("⚠️ <b>Brand Not Found</b>")
        + f"\n\nNo brand <code>{html.escape(brand_filter)}</code>.\n\n"
        f"<b>Available:</b> {preview}{more}\n\n"
        "<i>Example:</i> <code>/main STMY</code>"
    )


def build_bot_welcome_html(
    chat_id: int | str,
    uid: str,
    thread_id: int | None = None,
    is_forum: bool = False,
) -> str:
    lines: list[str] = [
        accounts_header_html("🤖 <b>Bot Ready</b>"),
        "",
        "◦ <code>/ping</code> — check bot is online",
        "◦ <code>/login &lt;id&gt;</code> — request OTP",
        "◦ <code>/main</code> — GCS account list",
        "◦ <code>/other &lt;USER&gt;</code> — shooter account list",
    ]
    return "\n".join(lines)


def build_login_request_accepted_html(
    profile: str,
    phone: str,
    brand: str | None = None,
    user: str | None = None,
) -> str:
    lines: list[str] = [
        accounts_header_html("✅ <b>Login Request</b>"),
        "",
    ]
    if brand:
        lines.append(f"<b>Brand</b>    ·  {html.escape(brand)}")
    if user:
        lines.append(f"<b>User</b>     ·  {html.escape(user)}")
    lines.append(f"<b>Profile</b>  ·  {html.escape(profile)}")
    lines.append(f"<b>Phone</b>    ·  <code>{html.escape(phone)}</code>")
    lines.extend(
        [
            "",
            "<i>Status · Waiting Login Section</i>",
            "",
            "1) Continue login on target device",
            "2) OTP will be sent to this chat",
        ]
    )
    return "\n".join(lines)


def build_forum_topic_error_html(topic_currency: str, account_currency: str) -> str:
    return (
        accounts_header_html("⚠️ <b>Wrong Topic</b>")
        + "\n\n"
        + f"This topic is <b>{html.escape(topic_currency)}</b> OTP.\n"
        + f"Account belongs to <b>{html.escape(account_currency)}</b>.\n\n"
        + f"Please use the <b>{html.escape(account_currency)}</b> OTP topic."
    )


_SYSTEM_STATUS_UI: dict[str, tuple[str, str]] = {
    "Banned": ("🚫", "Account Banned"),
    "Frozen": ("🧊", "Account Frozen"),
    "Expired": ("⏱", "Session Expired"),
    "Disconnected": ("🚨", "Session Disconnected"),
    "Pending Login": ("📵", "Pending Login"),
}

def pool_account_type_label(pool: str) -> str:
    if str(pool or "").strip().lower() == "shooter":
        return "( Shooter Account )"
    return "( GCS Account )"


def format_phone_display(phone: str) -> str:
    p = str(phone or "").strip()
    if not p:
        return "—"
    if p.startswith("+"):
        return p
    digits = "".join(c for c in p if c.isdigit())
    return f"+{digits}" if digits else p


def account_staff_display_name(acc: dict[str, Any], accounts_doc: dict[str, Any]) -> str:
    """Notification user from Sheet owner/user; show '-' if empty."""
    # Shooter + GCS: prefer user/owner from Sheet.
    for key in ("user_name", "user", "owner"):
        val = str(acc.get(key) or "").strip()
        if val:
            return val
    return "—"


def build_live_login_event_html(
    event: str,
    acc: dict[str, Any],
    accounts_doc: dict[str, Any],
    *,
    label: str = "",
    profile: str = "",
    detail: str = "",
) -> str:
    titles: dict[str, tuple[str, str]] = {
        "sms": ("📲", "Live Login — SMS Requested"),
        "otp": ("🔑", "Live Login — OTP Detected"),
        "success": ("✅", "Live Login — Success"),
        "failed": ("❌", "Live Login — Failed"),
        "finalize": ("✅", "Live Login — Finalized"),
        "wrong_otp": ("⚠️", "Live Login — Wrong OTP"),
        "waiting": ("⏳", "Live Login — Waiting OTP"),
    }
    emoji, title_text = titles.get(event, ("ℹ️", f"Live Login — {event}"))
    pool = "shooter" if label.upper() == "SHOOTER" else account_pool(acc)
    pool_tag = pool_account_type_label(pool)
    prof = profile or str(acc.get("profile_hint") or acc.get("id") or "?")
    staff = account_staff_display_name(acc, accounts_doc)
    number = format_phone_display(str(acc.get("phone") or ""))
    lines = [
        f"{emoji} <b>{html.escape(title_text)}</b>",
        "━━━━━━━━━━━━━━━━━━",
        f"Account: <b>{html.escape(prof)}</b> <i>{html.escape(pool_tag)}</i>",
        f"Number: <b>{html.escape(number)}</b>",
        f"User: <b>{html.escape(staff)}</b>",
    ]
    if detail.strip():
        lines.append(f"Detail: <b>{html.escape(detail.strip())}</b>")
    return "\n".join(lines)


def _live_login_notify_enabled() -> bool:
    return os.environ.get("TELEGRAM_LIVE_LOGIN_NOTIFY", "1").strip().lower() not in (
        "0",
        "false",
        "no",
        "off",
    )


def notify_live_login_event(
    acc: dict[str, Any],
    event: str,
    *,
    label: str = "",
    profile: str = "",
    detail: str = "",
    accounts_doc: dict[str, Any] | None = None,
) -> None:
    if not _live_login_notify_enabled():
        return
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    if not token:
        return
    doc = accounts_doc if accounts_doc is not None else load_json(accounts_json_path())
    msg = build_live_login_event_html(
        event,
        acc,
        doc,
        label=label,
        profile=profile,
        detail=detail,
    )
    send_login_status_message(token, msg, doc, acc)


_manual_login_last_alert: dict[str, float] = {}


def _manual_login_alert_enabled() -> bool:
    return os.environ.get("TELEGRAM_MANUAL_LOGIN_ALERT", "1").strip().lower() not in (
        "0",
        "false",
        "no",
        "off",
    )


def _manual_login_alert_cooldown_sec() -> int:
    return _env_int("TELEGRAM_MANUAL_LOGIN_ALERT_COOLDOWN_SEC", 300, minimum=30)


def _manual_login_scan_delay_sec() -> int:
    return _env_int("TELEGRAM_MANUAL_LOGIN_FOLLOWUP_SEC", 60, minimum=15)


def _listen_keep_device_label() -> str:
    return (os.environ.get("TELEGRAM_LISTEN_DEVICE_MODEL") or "FRIDAY_BO").strip() or "FRIDAY_BO"


async def _collect_non_friday_authorizations(
    client: TelegramClient,
    *,
    keep_device: str | None = None,
) -> list[dict[str, Any]]:
    from telethon.tl.functions.account import GetAuthorizationsRequest

    keep = (keep_device or _listen_keep_device_label()).lower()
    result = await client(GetAuthorizationsRequest())
    out: list[dict[str, Any]] = []
    for a in result.authorizations:
        if getattr(a, "current", False):
            continue
        device = str(getattr(a, "device_model", "") or "")
        if keep and keep in device.lower():
            continue
        date_active = getattr(a, "date_active", None)
        out.append(
            {
                "hash": int(getattr(a, "hash", 0) or 0),
                "device": device or "?",
                "platform": str(getattr(a, "platform", "") or "?"),
                "app_name": str(getattr(a, "app_name", "") or "?"),
                "app_version": str(getattr(a, "app_version", "") or "?"),
                "ip": str(getattr(a, "ip", "") or "?"),
                "country": str(getattr(a, "country", "") or ""),
                "region": str(getattr(a, "region", "") or ""),
                "date_active": date_active,
            }
        )
    return out


def _auth_active_age_sec(date_active: Any) -> float | None:
    if date_active is None:
        return None
    try:
        if isinstance(date_active, datetime):
            dt = date_active if date_active.tzinfo else date_active.replace(tzinfo=timezone.utc)
        else:
            dt = datetime.fromtimestamp(int(date_active), tz=timezone.utc)
        return max(0.0, time.time() - dt.timestamp())
    except (TypeError, ValueError, OSError):
        return None


def _manual_login_account_fields(
    acc: dict[str, Any],
    accounts_doc: dict[str, Any],
) -> tuple[str, str, str, str, str]:
    acc_id = str(acc.get("id") or "?")
    pool = account_pool(acc)
    prof = str(acc.get("profile_hint") or acc.get("detected_profile") or acc_id)
    pool_tag = pool_account_type_label(pool)
    staff = account_staff_display_name(acc, accounts_doc)
    number = format_phone_display(str(acc.get("phone") or ""))
    return acc_id, prof, pool_tag, staff, number


def _format_session_kv_pre(pairs: list[tuple[str, str]]) -> str:
    """Aligned key : value block (same style as list-sessions terminal output)."""
    if not pairs:
        return ""
    label_w = max(max(len(k) for k, _ in pairs), 9)
    body = "\n".join(f"{k:<{label_w}}: {v}" for k, v in pairs)
    return f"<pre>{html.escape(body)}</pre>"


def _format_ip_area_country(
    ip: str,
    region: str = "",
    country: str = "",
) -> str:
    """Format IP + location from Telegram Authorization.country / .region (Telegram geolocation)."""
    ip_clean = (ip or "").strip()
    if ip_clean in ("?", "—", "-", ""):
        ip_clean = ""
    area = (region or "").strip()
    country_clean = (country or "").strip()
    parts: list[str] = []
    for part in (area, country_clean):
        if not part:
            continue
        if part.lower() not in {p.lower() for p in parts}:
            parts.append(part)
    loc = ", ".join(parts)
    if ip_clean and loc:
        return f"{ip_clean} ({loc})"
    if ip_clean:
        return ip_clean
    if loc:
        return f"({loc})"
    return "—"


def _session_auth_display_fields(session: dict[str, Any]) -> dict[str, str]:
    device = str(session.get("device") or "?")
    platform = str(session.get("platform") or "?")
    app_name = str(session.get("app_name") or "?")
    app_version = str(session.get("app_version") or "").strip()
    app = f"{app_name} {app_version}".strip()
    hash_val = str(session.get("hash") if session.get("hash") is not None else "—")
    return {
        "device": f"{device} / {platform}",
        "app": app,
        "ip": _format_ip_area_country(
            str(session.get("ip") or ""),
            str(session.get("region") or ""),
            str(session.get("country") or ""),
        ),
        "hash": hash_val,
    }


def _staff_mention_html(row: dict[str, Any]) -> str:
    uname = str(row.get("telegram_username") or "").strip().lstrip("@")
    if uname:
        return f"@{html.escape(uname)}"
    tg_id = str(row.get("telegram_user_id") or row.get("chat_id") or "").strip()
    label = str(row.get("label") or row.get("id") or "user").strip()
    if tg_id.isdigit():
        return f'<a href="tg://user?id={tg_id}">{html.escape(label)}</a>'
    aid = str(row.get("id") or "").strip()
    if aid:
        return f"@{html.escape(aid)}"
    return ""


def build_admin_creator_cc_html(accounts_doc: dict[str, Any]) -> str:
    rows = accounts_doc.get("accounts", [])
    if not isinstance(rows, list):
        return ""
    creator = creator_account_id()
    seen: set[str] = set()
    tags: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        aid = str(row.get("id") or "").strip().lower()
        if not aid:
            continue
        if aid != creator and not _staff_row_is_admin(row):
            continue
        dedupe = str(row.get("telegram_user_id") or row.get("chat_id") or aid).strip()
        if not dedupe or dedupe in seen:
            continue
        seen.add(dedupe)
        tag = _staff_mention_html(row)
        if tag:
            tags.append(tag)
    if not tags:
        return ""
    return "cc : " + " ".join(tags)


def build_manual_login_detected_html(
    acc: dict[str, Any],
    accounts_doc: dict[str, Any],
    session: dict[str, Any],
) -> str:
    _, prof, _, staff, number = _manual_login_account_fields(acc, accounts_doc)
    fields = _session_auth_display_fields(session)
    pairs: list[tuple[str, str]] = [
        ("Account", prof),
        ("Phone", number),
        ("Staff", staff or "—"),
        ("Status", "OTP received without Friday"),
        ("Device", fields["device"]),
        ("App", fields["app"]),
        ("IP", fields["ip"]),
        ("Hash", fields["hash"]),
    ]
    lines = [
        "⚠ <b>Manual Login Detected!</b>",
        "",
        _format_session_kv_pre(pairs),
    ]
    cc = build_admin_creator_cc_html(accounts_doc)
    if cc:
        lines.extend(["", cc])
    return "\n".join(lines)


def notify_manual_login_detected(
    acc: dict[str, Any],
    session: dict[str, Any],
    *,
    accounts_doc: dict[str, Any] | None = None,
) -> None:
    if not _manual_login_alert_enabled():
        return
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    if not token:
        return
    doc = accounts_doc if accounts_doc is not None else load_json(accounts_json_path())
    msg = build_manual_login_detected_html(acc, doc, session)
    send_login_status_message(token, msg, doc, acc)


async def _manual_login_success_scan(
    client: TelegramClient,
    acc: dict[str, Any],
    accounts_doc: dict[str, Any],
    baseline_hashes: set[int],
) -> None:
    if not _manual_login_alert_enabled():
        return
    await asyncio.sleep(_manual_login_scan_delay_sec())
    try:
        auths = await _collect_non_friday_authorizations(client)
    except Exception as e:
        logger.debug("manual login scan failed for %s: %s", acc.get("id"), e)
        return
    new_sessions = [
        a
        for a in auths
        if int(a.get("hash") or 0) and int(a.get("hash") or 0) not in baseline_hashes
    ]
    if not new_sessions:
        return
    acc_id_str = str(acc.get("id") or "")
    now = time.time()
    cd = _manual_login_alert_cooldown_sec()
    if now - _manual_login_last_alert.get(acc_id_str, 0.0) < cd:
        return
    _manual_login_last_alert[acc_id_str] = now

    def _sort_key(s: dict[str, Any]) -> float:
        age = _auth_active_age_sec(s.get("date_active"))
        return age if age is not None else 999999.0

    session = min(new_sessions, key=_sort_key)
    notify_manual_login_detected(acc, session, accounts_doc=accounts_doc)


def build_system_status_html(
    status: str,
    *,
    profile: str,
    pool: str,
    phone: str = "",
    user_name: str = "",
    account_id: str = "",
) -> str:
    """System Status — bold on values (details), not field labels."""
    emoji, title = _SYSTEM_STATUS_UI.get(status, ("⚠️", f"Account {status}"))
    display_name = (profile or account_id or "—").strip()
    pool_tag = pool_account_type_label(pool)
    staff = (user_name or "—").strip()
    number = format_phone_display(phone)
    account_detail = f"{html.escape(display_name)} {pool_tag}"
    return "\n".join(
        [
            f"<b>{title} {emoji}</b>",
            "━━━━━━━━━━━━━━━━━━",
            f"Account: <b>{account_detail}</b>",
            f"Number: <b>{html.escape(number)}</b>",
            f"User: <b>{html.escape(staff)}</b>",
        ]
    )


def listener_account_display_name(
    acc: dict[str, Any],
    acc_id: str,
    profile: str = "",
) -> str:
    """Listener summary lists — show profile name, not account id when available."""
    name = (profile or str(acc.get("profile_hint") or "")).strip()
    if not name or name.lower() == acc_id.lower():
        return acc_id
    return name


def build_listener_started_html(
    gcs_active: int,
    shooter_active: int,
    expired: list[str],
    skipped: list[str],
    gcs_total: int,
    shooter_total: int,
) -> str:
    active_count = gcs_active + shooter_active
    total_accounts = gcs_total + shooter_total
    lines: list[str] = [
        "<b>Listener Started</b> 🔔",
        "━━━━━━━━━━━━━━━━━━",
        f"Active: <b>{active_count}</b>",
        f"  · GCS: <b>{gcs_active} / {gcs_total}</b>",
        f"  · Shooter: <b>{shooter_active} / {shooter_total}</b>",
        "",
    ]
    if expired:
        lines.append(f"Expired: <b>{len(expired)}</b>")
        for e in expired[:8]:
            lines.append(f"  · <b>{html.escape(e)}</b>")
        if len(expired) > 8:
            lines.append(f"  · <b>… +{len(expired) - 8} more</b>")
    if skipped:
        lines.append(f"Skipped: <b>{len(skipped)}</b> (not logged in)")
    lines.append(f"Total: <b>{total_accounts}</b> accounts")
    return "\n".join(lines)


def build_listener_stopped_html(
    gcs_active: int,
    shooter_active: int,
    gcs_total: int,
    shooter_total: int,
    *,
    reason: str = "",
) -> str:
    active_count = gcs_active + shooter_active
    total_accounts = gcs_total + shooter_total
    lines: list[str] = [
        "<b>Listener Stopped</b> ❌",
        "━━━━━━━━━━━━━━━━━━",
        f"Was active: <b>{active_count}</b>",
        f"  · GCS: <b>{gcs_active} / {gcs_total}</b>",
        f"  · Shooter: <b>{shooter_active} / {shooter_total}</b>",
        "",
        f"Total: <b>{total_accounts}</b> accounts",
    ]
    if reason.strip():
        lines.append(f"Reason: <b>{html.escape(reason.strip())}</b>")
    return "\n".join(lines)


def _listener_stop_notify_enabled() -> bool:
    return os.environ.get("TELEGRAM_LISTEN_STOP_NOTIFY", "1").strip().lower() not in (
        "0",
        "false",
        "no",
        "off",
    )


def build_session_disconnected_html(
    acc: dict[str, Any],
    accounts_doc: dict[str, Any],
    *,
    profile: str = "",
) -> str:
    acc_id = str(acc.get("id") or "?")
    pool = account_pool(acc)
    prof = profile or str(acc.get("detected_profile") or acc.get("profile_hint") or acc_id)
    return build_system_status_html(
        "Disconnected",
        profile=prof,
        pool=pool,
        phone=str(acc.get("phone") or ""),
        user_name=account_staff_display_name(acc, accounts_doc),
        account_id=acc_id,
    )


def build_sessions_disconnected_batch_html(
    items: list[tuple[dict[str, Any], str]],
    accounts_doc: dict[str, Any],
) -> str:
    lines: list[str] = [
        "🚨 <b>Sessions Disconnected</b>",
        "━━━━━━━━━━━━━━━━━━",
        f"<b>{len(items)}</b> account(s) could not reconnect after a network outage.",
        "",
    ]
    for acc, profile in items[:12]:
        acc_id = str(acc.get("id") or "?")
        pool = account_pool(acc)
        prof = profile or str(acc.get("detected_profile") or acc.get("profile_hint") or acc_id)
        lines.append(
            f"· <b>{html.escape(acc_id)}</b> — {html.escape(prof)} "
            f"<i>({html.escape(pool_account_type_label(pool))})</i>"
        )
    if len(items) > 12:
        lines.append(f"· <b>… +{len(items) - 12} lagi</b>")
    lines.append("")
    lines.append("<i>Brief WiFi drops usually auto-reconnect without a notification.</i>")
    return "\n".join(lines)


_disconnect_last_alert: dict[str, float] = {}
_disconnect_batch_queue: list[dict[str, Any]] = []
_disconnect_batch_lock: asyncio.Lock | None = None
_disconnect_batch_flush_task: asyncio.Task[None] | None = None


def _disconnect_watch_config() -> tuple[int, int, int, int, int]:
    grace = _env_int("TELEGRAM_DISCONNECT_GRACE_SEC", 90, minimum=0)
    attempts = _env_int("TELEGRAM_DISCONNECT_RECONNECT_ATTEMPTS", 5, minimum=1)
    delay = _env_int("TELEGRAM_DISCONNECT_RECONNECT_DELAY_SEC", 15, minimum=3)
    cooldown = _env_int("TELEGRAM_DISCONNECT_ALERT_COOLDOWN_SEC", 900, minimum=60)
    batch_min = _env_int("TELEGRAM_DISCONNECT_BATCH_MIN", 3, minimum=2)
    return grace, attempts, delay, cooldown, batch_min


async def _try_reconnect_listener_client(
    cl: TelegramClient,
    attempts: int,
    delay_sec: int,
    tag: str,
    acc_id: str,
) -> bool:
    for attempt in range(attempts):
        try:
            if not cl.is_connected():
                await cl.connect()
            if not await cl.is_user_authorized():
                return False
            await asyncio.wait_for(cl.get_me(), timeout=45)
            return True
        except Exception as e:
            print(
                f"  [{tag}] {acc_id} reconnect {attempt + 1}/{attempts}: {type(e).__name__}: {e}",
                flush=True,
            )
        if attempt + 1 < attempts:
            await asyncio.sleep(delay_sec)
    return False


async def _enqueue_disconnect_alert(
    acc_info: dict[str, Any],
    profile: str,
    tag: str,
    token: str,
    accounts_doc: dict[str, Any],
    pool_name: str,
) -> None:
    global _disconnect_batch_flush_task
    if _disconnect_batch_lock is None:
        return
    entry = {
        "acc": acc_info,
        "profile": profile,
        "tag": tag,
        "pool_name": pool_name,
    }
    async with _disconnect_batch_lock:
        _disconnect_batch_queue.append(entry)
        need_task = _disconnect_batch_flush_task is None or _disconnect_batch_flush_task.done()
        if need_task:
            window = _env_int("TELEGRAM_DISCONNECT_BATCH_WINDOW_SEC", 45, minimum=5)
            _disconnect_batch_flush_task = asyncio.create_task(
                _flush_disconnect_alerts(token, accounts_doc, window)
            )


async def _flush_disconnect_alerts(
    token: str,
    accounts_doc: dict[str, Any],
    window_sec: int,
) -> None:
    await asyncio.sleep(window_sec)
    if _disconnect_batch_lock is None:
        return
    async with _disconnect_batch_lock:
        batch = list(_disconnect_batch_queue)
        _disconnect_batch_queue.clear()

    if not batch:
        return

    batch_min = _env_int("TELEGRAM_DISCONNECT_BATCH_MIN", 3, minimum=2)
    if len(batch) >= batch_min:
        items = [(e["acc"], str(e["profile"])) for e in batch]
        msg = build_sessions_disconnected_batch_html(items, accounts_doc)
        send_login_status_message(token, msg, accounts_doc)
        print(f"  [LISTEN] batch disconnect alert: {len(batch)} account(s)", flush=True)
    else:
        for e in batch:
            acc_info = e["acc"]
            profile = str(e["profile"])
            alert = build_session_disconnected_html(acc_info, accounts_doc, profile=profile)
            send_login_status_message(token, alert, accounts_doc)

    for e in batch:
        acc_info = e["acc"]
        acc_id = str(acc_info.get("id", "?"))
        pool_name = str(e["pool_name"])
        profile = str(e["profile"])
        _queue_sheet_status(
            acc_id,
            pool_name,
            "disconnected",
            profile,
            phone=str(acc_info.get("phone") or ""),
            session_user="Disconnected",
            session_friday="Disconnected",
            allow_instant=False,
        )


_account_status_cache: dict[str, str] = {}


def _account_status_cache_key(acc: dict[str, Any]) -> str:
    try:
        import sheets_sync

        phone = sheets_sync.norm_phone(str(acc.get("phone") or ""))
    except Exception:
        phone = ""
    return phone or str(acc.get("id") or "").strip() or "?"


def _known_account_status(acc: dict[str, Any]) -> str:
    key = _account_status_cache_key(acc)
    if key in _account_status_cache:
        return _account_status_cache[key]
    try:
        import sheets_sync

        phone = sheets_sync.norm_phone(str(acc.get("phone") or ""))
        row = sheets_sync.collect_status_from_queue(project_root()).get(phone, {})
        st = str(row.get("session_friday") or row.get("session_user") or "").strip()
        if st:
            _account_status_cache[key] = st
        return st
    except Exception:
        return ""


def _warm_account_status_cache() -> None:
    try:
        import sheets_sync

        for phone, row in sheets_sync.collect_status_from_queue(project_root()).items():
            st = str(row.get("session_friday") or row.get("session_user") or "").strip()
            if st and phone:
                _account_status_cache[phone] = st
    except Exception:
        pass


def _account_status_changed(acc: dict[str, Any], new_status: str) -> bool:
    new = str(new_status or "").strip()
    if not new:
        return False
    prev = _known_account_status(acc)
    return not (prev and prev.lower() == new.lower())


def _mark_account_status_known(acc: dict[str, Any], status: str) -> None:
    _account_status_cache[_account_status_cache_key(acc)] = str(status or "").strip()


_frozen_notify_last: dict[str, float] = {}
_expired_notify_last: dict[str, float] = {}


def _status_notify_cooldown_ok(acc: dict[str, Any], status: str) -> bool:
    st = str(status or "").strip()
    if st == "Frozen":
        sec = _env_int("TELEGRAM_NOTIFY_FROZEN_COOLDOWN_SEC", 86400, minimum=0)
        store = _frozen_notify_last
    elif st == "Expired":
        sec = _env_int("TELEGRAM_NOTIFY_EXPIRED_COOLDOWN_SEC", 86400, minimum=0)
        store = _expired_notify_last
    else:
        return True
    if sec <= 0:
        return True
    key = _account_status_cache_key(acc)
    last = store.get(key, 0.0)
    return time.time() - last >= sec


def _frozen_notify_cooldown_ok(acc: dict[str, Any]) -> bool:
    return _status_notify_cooldown_ok(acc, "Frozen")


def _mark_status_notified(acc: dict[str, Any], status: str) -> None:
    st = str(status or "").strip()
    key = _account_status_cache_key(acc)
    if st == "Frozen":
        _frozen_notify_last[key] = time.time()
    elif st == "Expired":
        _expired_notify_last[key] = time.time()


def _mark_frozen_notified(acc: dict[str, Any]) -> None:
    _mark_status_notified(acc, "Frozen")


def _should_notify_account_status(
    acc: dict[str, Any],
    status: str,
    *,
    frozen_confirmed: bool = False,
    from_listen: bool = False,
) -> bool:
    """Gate Telegram alerts — Frozen/Expired never from LISTEN; cooldown on repeat."""
    st = str(status or "").strip()
    if from_listen and st in ("Frozen", "Expired", "Disconnected"):
        return False
    if not _system_status_notify_enabled(status):
        return False
    if st == "Frozen":
        if not frozen_confirmed:
            return False
        if not _frozen_notify_cooldown_ok(acc):
            return False
    elif st == "Expired":
        if not _status_notify_cooldown_ok(acc, "Expired"):
            return False
    return True


def _publish_account_status(
    acc: dict[str, Any],
    pool: str,
    user_st: str,
    *,
    token: str,
    accounts_doc: dict[str, Any],
    profile: str = "",
    note: str = "",
    notify: bool = True,
    frozen_confirmed: bool = False,
    from_listen: bool = False,
) -> bool:
    """Queue Sheet + Telegram only when status actually changed."""
    if not _account_status_changed(acc, user_st):
        return False
    acc_id = str(acc.get("id") or "?")
    _mark_account_status_known(acc, user_st)
    _queue_sheet_status(
        acc_id,
        pool,
        user_st.lower(),
        note or profile,
        phone=str(acc.get("phone") or ""),
        session_user=user_st,
        session_friday=_session_friday_for_account_status(user_st),
        allow_instant=False,
    )
    if notify and _should_notify_account_status(
        acc, user_st, frozen_confirmed=frozen_confirmed, from_listen=from_listen
    ):
        notify_system_account_status(
            token,
            accounts_doc,
            acc,
            user_st,
            profile=profile or str(acc.get("profile_hint") or acc_id),
        )
        if str(user_st or "").strip() == "Frozen":
            _mark_frozen_notified(acc)
        elif str(user_st or "").strip() == "Expired":
            _mark_status_notified(acc, "Expired")
    return True


def notify_system_account_status(
    token: str,
    accounts_doc: dict[str, Any],
    acc: dict[str, Any],
    session_user: str,
    *,
    profile: str = "",
) -> None:
    if session_user not in _SYSTEM_STATUS_UI:
        return
    acc_id = str(acc.get("id") or "?")
    pool = account_pool(acc)
    prof = profile or str(acc.get("profile_hint") or acc_id)
    msg = build_system_status_html(
        session_user,
        profile=prof,
        pool=pool,
        phone=str(acc.get("phone") or ""),
        user_name=account_staff_display_name(acc, accounts_doc),
        account_id=acc_id,
    )
    send_login_status_message(token, msg, accounts_doc)


def format_otp_alert_message(code: str, password_display: str, template: str | None = None) -> str:
    # blockquote + line = slightly wider bubble for Code & 2FA buttons
    default_title = "<blockquote>🔐 <b>OTP ALERT</b>\n━━━━━━━━━━━━━━━━━━</blockquote>"
    tpl = (template or "").strip() or default_title
    msg = _unescape_telegram_html(tpl)
    return msg.replace("{code}", f"<b>{html.escape(code)}</b>").replace(
        "{password}", f"<b>{password_display}</b>"
    )


def send_message(
    token: str,
    chat_id: str,
    text: str,
    parse_mode: str | None = None,
    message_thread_id: int | None = None,
    reply_markup: dict[str, Any] | None = None,
) -> dict:
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    body: dict[str, Any] = {"chat_id": chat_id, "text": text}
    if parse_mode:
        body["parse_mode"] = parse_mode
    if message_thread_id:
        body["message_thread_id"] = message_thread_id
    if reply_markup:
        body["reply_markup"] = reply_markup
    data = json.dumps(body).encode("utf-8")
    retries = _env_int("TELEGRAM_HTTP_RETRIES", 3, minimum=1)
    timeout = _env_int("TELEGRAM_HTTP_TIMEOUT_SEC", 30, minimum=5)
    last_err: BaseException | None = None
    for attempt in range(retries):
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json; charset=utf-8"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8")
            return json.loads(raw)
        except urllib.error.HTTPError as e:
            last_err = e
            if e.code in (429, 500, 502, 503, 504) and attempt + 1 < retries:
                retry_after = 1.0
                try:
                    err_body = e.read().decode("utf-8", errors="replace")
                    parsed = json.loads(err_body)
                    params = parsed.get("parameters") or {}
                    ra = params.get("retry_after")
                    if ra is not None:
                        retry_after = min(float(ra), 60.0)
                except (TypeError, ValueError, json.JSONDecodeError, OSError):
                    pass
                time.sleep(retry_after + attempt * 0.5)
                continue
            raise
        except (urllib.error.URLError, TimeoutError, ConnectionResetError, OSError) as e:
            last_err = e
            if attempt + 1 < retries:
                time.sleep(0.8 * (2**attempt))
                continue
            raise
    raise RuntimeError("send_message: retry logic error") from last_err


def resolve_targets(raw: dict[str, Any], account_key: str | None, broadcast: bool) -> list[str]:
    by_id: dict[str, str] = {}
    rows = raw.get("accounts")
    if isinstance(rows, list):
        for row in rows:
            if not isinstance(row, dict):
                continue
            aid = row.get("id")
            cid = row.get("chat_id")
            if aid and cid:
                by_id[str(aid).strip()] = str(cid).strip()

    last_chat = read_last_chat_id(state_json_path())
    legacy = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    prefer_last = os.environ.get("TELEGRAM_PREFER_LAST_CHAT", "1").strip().lower() not in (
        "0",
        "false",
        "no",
        "off",
    )

    if broadcast:
        return list(by_id.values())
    if account_key:
        if account_key in by_id:
            return [by_id[account_key]]
        raise ValueError(f'id "{account_key}" not found in accounts')
    if prefer_last and last_chat:
        return [last_chat]
    env_acc = os.environ.get("TELEGRAM_ACCOUNT", "").strip()
    if env_acc and env_acc in by_id:
        return [by_id[env_acc]]
    default_acc = str(raw.get("default_account") or "").strip()
    if default_acc and default_acc in by_id:
        return [by_id[default_acc]]
    if legacy:
        return [legacy]
    if last_chat:
        return [last_chat]
    raise ValueError("No valid target chat")


def notify_targets_for_acc(accounts_doc: dict[str, Any], acc: dict[str, Any]) -> list[str]:
    if acc.get("notify_chat_id"):
        return [str(acc["notify_chat_id"]).strip()]
    try:
        return resolve_targets(accounts_doc, str(acc.get("notify_account") or acc.get("id") or "").strip(), False)
    except ValueError:
        return []


def login_status_thread_id(accounts_doc: dict[str, Any] | None = None) -> int | None:
    """Forum topic for system notifications (listener, disconnect, login status)."""
    raw = os.environ.get("TELEGRAM_LOGIN_STATUS_THREAD_ID", "").strip()
    if raw:
        return to_int(raw)
    doc = accounts_doc if accounts_doc is not None else load_json(accounts_json_path())
    forum = doc.get("forum")
    if not isinstance(forum, dict):
        return None
    status_chat = os.environ.get("TELEGRAM_LOGIN_STATUS_CHAT_ID", "").strip()
    forum_chat = str(forum.get("chat_id") or "").strip()
    if status_chat and forum_chat and status_chat != forum_chat:
        return None
    topics = forum.get("topics")
    if not isinstance(topics, dict):
        return None
    for key in ("SYSTEM", "System Status", "system_status"):
        topic = topics.get(key)
        if isinstance(topic, dict):
            tid = to_int(topic.get("thread_id"))
            if tid:
                return tid
    return None


def login_status_notify_targets(
    accounts_doc: dict[str, Any],
    acc: dict[str, Any] | None = None,
) -> list[tuple[str, int | None]]:
    """Tujuan notifikasi sistem: (chat_id, message_thread_id). Bukan chat requester OTP."""
    raw = os.environ.get("TELEGRAM_LOGIN_STATUS_CHAT_ID", "").strip()
    thread_id = login_status_thread_id(accounts_doc)
    if raw:
        return [(x.strip(), thread_id) for x in raw.split(",") if x.strip()]
    if acc:
        return [(cid, None) for cid in notify_targets_for_acc(accounts_doc, acc)]
    for row in accounts_doc.get("accounts", []):
        if not isinstance(row, dict):
            continue
        cid = str(row.get("chat_id", "")).strip()
        if cid:
            return [(cid, None)]
    return []


def status_preview_chat_id(accounts_doc: dict[str, Any] | None = None) -> str | None:
    """DM for notification preview before forum topic (e.g. geri_work)."""
    raw = os.environ.get("TELEGRAM_STATUS_PREVIEW_CHAT_ID", "").strip()
    if raw:
        return raw
    doc = accounts_doc if accounts_doc is not None else load_json(accounts_json_path())
    creator = os.environ.get("TELEGRAM_CREATOR_ACCOUNT_ID", "geri_work").strip().lower()
    for row in doc.get("accounts", []):
        if not isinstance(row, dict):
            continue
        if str(row.get("id", "")).strip().lower() == creator:
            cid = str(row.get("chat_id", "")).strip()
            if cid:
                return cid
    return None


def status_preview_only() -> bool:
    """1 = hanya DM preview, belum ke forum topic."""
    return os.environ.get("TELEGRAM_STATUS_PREVIEW_ONLY", "0").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def send_login_status_message(
    token: str,
    text: str,
    accounts_doc: dict[str, Any] | None = None,
    acc: dict[str, Any] | None = None,
    parse_mode: str = "HTML",
) -> None:
    doc = accounts_doc if accounts_doc is not None else load_json(accounts_json_path())
    preview = status_preview_chat_id(doc)
    if preview:
        try:
            send_message(token, preview, text, parse_mode, None)
        except Exception:
            pass
    if preview and status_preview_only():
        return
    for chat_id, thread_id in login_status_notify_targets(doc, acc):
        try:
            send_message(token, chat_id, text, parse_mode, thread_id)
        except Exception:
            pass


def parse_peer_ids(value: Any, default_ids: list[int]) -> list[int]:
    if isinstance(value, list):
        out = [int(x) for x in value if str(x).strip().isdigit()]
        return out or default_ids
    out: list[int] = []
    for p in str(value or "").split(","):
        s = p.strip()
        if s.isdigit():
            out.append(int(s))
    return out or default_ids


def normalize_session(root: Path, value: str | None, default_name: str) -> Path:
    s = (value or "").strip() or default_name
    p = Path(s)
    if not p.is_absolute() and p.parent == Path("."):
        p = Path("telegram_session") / p
    return p if p.is_absolute() else (root / p).resolve()


def to_int(v: Any) -> int | None:
    try:
        return int(str(v).strip())
    except Exception:
        return None


def load_otp_accounts(raw: dict[str, Any], root: Path, default_peers: list[int]) -> list[dict[str, Any]]:
    rows = raw.get("otp_accounts")
    out: list[dict[str, Any]] = []
    if isinstance(rows, list) and rows:
        for i, row in enumerate(rows, start=1):
            if not isinstance(row, dict):
                continue
            aid = str(row.get("id") or f"acc{i}").strip()
            api_id = to_int(row.get("api_id") if row.get("api_id") is not None else raw.get("api_id"))
            api_hash = str(row.get("api_hash") or raw.get("api_hash") or "").strip()
            if not aid or api_id is None or not api_hash:
                continue
            enabled = str(row.get("enabled", True)).strip().lower() not in ("0", "false", "no", "off")
            if not enabled:
                continue
            out.append(
                {
                    "id": aid,
                    "api_id": api_id,
                    "api_hash": api_hash,
                    "phone": str(row.get("phone") or "").strip() or None,
                    "password": str(row.get("password") or "").strip() or None,
                    "session": normalize_session(root, row.get("session"), f"{aid}.session"),
                    "notify_account": str(row.get("notify_account") or aid).strip(),
                    "notify_chat_id": str(row.get("notify_chat_id") or "").strip() or None,
                    "profile_hint": str(row.get("profile_hint") or "").strip() or None,
                    "peer_ids": parse_peer_ids(row.get("peer_ids"), default_peers),
                    "brand": str(row.get("brand") or "").strip() or None,
                    "device_id": str(row.get("device_id") or "").strip() or None,
                    "pool": "gcs",
                }
            )
        return out
    return out


def derive_otp_brand(
    row: dict[str, Any],
    brands_cfg: dict[str, dict[str, Any]] | None = None,
) -> str:
    """Brand grouping: saved `brand`, id prefix, then explicit Device ID (MYR-SB-001)."""
    try:
        import sheets_sync
    except Exception:
        sheets_sync = None  # type: ignore[assignment]

    raw_b = row.get("brand")
    if raw_b is not None and str(raw_b).strip():
        b = str(raw_b).strip().upper()
        if sheets_sync is not None:
            if not sheets_sync.is_currency_code(b):
                return b
        elif b not in ("MYR", "SGD", "USD", "USC", "KHR"):
            return b

    aid = str(row.get("id") or "").strip()
    if sheets_sync is not None:
        resolved = sheets_sync.resolve_brand_from_id(aid, brands_cfg)
        if resolved:
            return resolved

    device_id = str(row.get("device_id") or "").strip()
    if device_id and sheets_sync is not None:
        currency, code = sheets_sync.parse_device_id(device_id)
        if currency and code:
            inferred = sheets_sync.infer_gcs_brand(
                device_id=device_id,
                account_id=aid,
                brand=str(row.get("brand") or ""),
                brands_cfg=brands_cfg,
            )
            if inferred:
                return inferred

    if aid and aid.upper() not in ("GCS", "SH", "UNKNOWN"):
        bare = aid.split("_", 1)[0].upper() if "_" in aid else aid.upper()
        if sheets_sync is not None:
            if not sheets_sync.is_currency_code(bare) and len(bare) >= 3:
                return bare
        elif bare not in ("MYR", "SGD", "USD", "USC", "KHR") and len(bare) >= 3:
            return bare
    return "UNKNOWN"


def group_otp_rows_by_brand(
    rows: list[dict[str, Any]],
    brands_cfg: dict[str, dict[str, Any]] | None = None,
) -> dict[str, list[dict[str, Any]]]:
    by: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        b = derive_otp_brand(row, brands_cfg)
        by.setdefault(b, []).append(row)
    for b in by:
        by[b].sort(key=lambda r: (str(r.get("profile_hint") or r.get("id") or "")).lower())
    return dict(sorted(by.items(), key=lambda kv: kv[0].lower()))


def load_shooter_accounts(raw: dict[str, Any]) -> list[dict[str, Any]]:
    """Shooter account (separate from GCS). Requires owner field, e.g. GERI."""
    rows = raw.get("shooter_accounts")
    out: list[dict[str, Any]] = []
    if not isinstance(rows, list):
        return out
    for i, row in enumerate(rows, start=1):
        if not isinstance(row, dict):
            continue
        enabled = str(row.get("enabled", True)).strip().lower() not in ("0", "false", "no", "off")
        if not enabled:
            continue
        owner = str(row.get("owner") or row.get("shooter_user") or row.get("user") or "").strip().upper()
        if not owner:
            continue
        aid = str(row.get("id") or f"shooter{i}").strip()
        brand_raw = str(row.get("brand") or "").strip()
        out.append(
            {
                "id": aid,
                "owner": owner,
                "profile_hint": str(row.get("profile_hint") or "").strip() or None,
                "phone": str(row.get("phone") or "").strip() or None,
                "brand": brand_raw.upper() if brand_raw else None,
                "remark": str(row.get("remark") or "").strip() or None,
                "currency": str(row.get("currency") or raw.get("shooter_currency") or "MYR").strip().upper(),
            }
        )
    return out


def load_shooter_login_accounts(
    raw: dict[str, Any], root: Path, default_peers: list[int] | None = None
) -> list[dict[str, Any]]:
    """Shooter accounts with Telethon credentials (for login-all-shooter / listen)."""
    if default_peers is None:
        default_peers = parse_peer_ids(os.environ.get("TELEGRAM_OTP_PEER_IDS", "777000"), [777000])
    rows = raw.get("shooter_accounts")
    out: list[dict[str, Any]] = []
    if not isinstance(rows, list):
        return out
    for i, row in enumerate(rows, start=1):
        if not isinstance(row, dict):
            continue
        enabled = str(row.get("enabled", True)).strip().lower() not in ("0", "false", "no", "off")
        if not enabled:
            continue
        owner = str(row.get("owner") or row.get("shooter_user") or row.get("user") or "").strip().upper()
        if not owner:
            continue
        aid = str(row.get("id") or f"shooter{i}").strip()
        api_id = to_int(row.get("api_id") if row.get("api_id") is not None else raw.get("api_id"))
        api_hash = str(row.get("api_hash") or raw.get("api_hash") or "").strip()
        phone = str(row.get("phone") or "").strip()
        if not aid or api_id is None or not api_hash or not phone:
            continue
        brand_raw = str(row.get("brand") or "").strip()
        default_session = f"telegram_session/shooter/{aid}"
        default_notify = (
            str(row.get("notify_account") or "").strip()
            or str(raw.get("shooter_notify_account") or "").strip()
            or os.environ.get("TELEGRAM_ACCOUNT", "").strip()
            or "geri_work"
        )
        out.append(
            {
                "id": aid,
                "owner": owner,
                "api_id": api_id,
                "api_hash": api_hash,
                "phone": phone,
                "password": str(row.get("password") or "").strip() or None,
                "session": normalize_session(root, row.get("session"), default_session),
                "profile_hint": str(row.get("profile_hint") or "").strip() or None,
                "brand": brand_raw.upper() if brand_raw else None,
                "remark": str(row.get("remark") or "").strip() or None,
                "pool": "shooter",
                "currency": str(row.get("currency") or raw.get("shooter_currency") or "MYR").strip().upper(),
                "notify_account": default_notify,
                "notify_chat_id": str(row.get("notify_chat_id") or "").strip() or None,
                "peer_ids": parse_peer_ids(row.get("peer_ids"), default_peers),
            }
        )
    return out


SHOOTER_DEFAULT_CURRENCY = "MYR"


def topic_currency_from_update(update: Update) -> str | None:
    """Currency for the forum topic the user is in, or None (general chat / DM)."""
    chat = update.effective_chat
    em = update.effective_message
    if not chat or not em:
        return None
    thread_id = getattr(em, "message_thread_id", None)
    if not thread_id:
        return None
    try:
        doc = load_json(accounts_json_path())
        return _forum_thread_to_currency(doc, chat.id, thread_id)
    except Exception:
        return None


def group_channel_topic_hint(*, topic_currency: str | None = None) -> str:
    """Staff-facing hint: GCS uses matching topic; shooter stays on MYR topic."""
    shooter = html.escape(SHOOTER_DEFAULT_CURRENCY)
    if topic_currency:
        cur = html.escape(str(topic_currency).strip().upper())
        return (
            f"You are in the <b>{cur}</b> topic — use <code>/main</code> and <code>/login</code> here "
            f"for <b>{cur}</b> GCS accounts.\n"
            f"Shooter accounts: use <code>/other</code> in the <b>{shooter}</b> topic."
        )
    return (
        f"<b>GCS:</b> use the topic that matches the account (SGD, MYR, …).\n"
        f"<b>Shooter:</b> use the <b>{shooter}</b> topic only."
    )


def account_pool(acc: dict[str, Any]) -> str:
    return str(acc.get("pool") or "gcs").strip().lower()


def account_currency_for_request(acc: dict[str, Any], brands_cfg: dict[str, dict[str, Any]]) -> str:
    if account_pool(acc) == "shooter":
        return str(acc.get("currency") or SHOOTER_DEFAULT_CURRENCY).strip().upper()
    return derive_brand_currency(derive_otp_brand(acc, brands_cfg), brands_cfg)


def profile_name_from_me(me: Any, fallback: str = "") -> str:
    full = " ".join(
        x for x in [getattr(me, "first_name", None), getattr(me, "last_name", None)] if x
    ).strip()
    uname = getattr(me, "username", None) or ""
    return full or uname or fallback


def account_status_from_me(me: Any) -> str:
    """Map get_me() → Active / Banned / Frozen / Expired.

    Frozen only when Telegram sets restricted=True (full restriction flag).
    restriction_reason alone is NOT used — too many false positives on CS accounts.
    """
    if not me:
        return "Expired"
    if getattr(me, "deleted", False):
        return "Banned"
    if getattr(me, "restricted", False):
        return "Frozen"
    return "Active"


def frozen_ui_probe_enabled() -> bool:
    """Health-check only: probe Saved Messages for UI freeze (FROZEN_* errors)."""
    return os.environ.get("TELEGRAM_FROZEN_UI_PROBE", "1").strip().lower() not in (
        "0",
        "false",
        "no",
        "off",
    )


def _exception_is_telegram_frozen(exc: BaseException) -> bool:
    name = type(exc).__name__.lower()
    msg = str(exc).lower()
    combined = f"{name} {msg}"
    if "frozen_method_invalid" in name or "frozen_participant" in combined:
        return True
    if "account is frozen" in combined or "your account is frozen" in combined:
        return True
    try:
        import sheets_sync

        return sheets_sync.classify_account_status(exc) == "Frozen"
    except Exception:
        return False


async def probe_frozen_ui_via_saved_messages(client: TelegramClient) -> bool | None:
    """
    Harmless active probe for Telegram UI freeze (get_me().restricted may stay False).
    True=Frozen, False=Active, None=unknown (keep Active).
    """
    probe_text = (os.environ.get("TELEGRAM_FROZEN_UI_PROBE_TEXT") or ".").strip() or "."
    try:
        sent = await client.send_message("me", probe_text)
        try:
            mid = int(getattr(sent, "id", 0) or 0)
            if mid:
                await client.delete_messages("me", [mid])
        except Exception:
            pass
        return False
    except Exception as e:
        if _exception_is_telegram_frozen(e):
            return True
        logger.debug("frozen ui probe non-frozen error: %s", e)
        return None


def sync_probe_frozen_ui(client: TelegramClient) -> bool | None:
    """Sync wrapper for health-check temp client."""
    try:
        if client.is_connected():
            return client.loop.run_until_complete(probe_frozen_ui_via_saved_messages(client))
    except Exception as e:
        logger.debug("sync frozen ui probe failed: %s", e)
    return None


SPAMBOT_PEER = "SpamBot"

_SPAMBOT_OK_PHRASES = (
    "good news",
    "no limits",
    "free as a bird",
    "not limited",
    "not frozen",
)

# UI freeze + Terms violation block (SpamBot). NOT generic "limited" soft-limit.
_SPAMBOT_FROZEN_PHRASES = (
    "your account is frozen",
    "account is frozen",
    "this account is frozen",
    "account was frozen",
    "accounts are frozen",
    "account was blocked",
    "was blocked for violations",
    "violations of the telegram",
    "read-only mode",
    "can't send messages or take actions",
    "cannot send messages or take actions",
    "appeal via @spambot before",
    "your account will be deleted",
)

_SPAMBOT_SOFT_LIMIT_PHRASES = (
    "limited",
    "restrict",
    "anti-spam",
    "unfortunately",
    "harsh response",
    "won't be able to send",
    "will not be able to send",
    "bad news",
    "done something that triggered",
)


def frozen_spambot_probe_enabled() -> bool:
    """Health-check @SpamBot probe — strict parser, newest reply only (not LISTEN)."""
    return os.environ.get("TELEGRAM_FROZEN_SPAMBOT_PROBE", "1").strip().lower() not in (
        "0",
        "false",
        "no",
        "off",
    )


def spambot_frozen_check_enabled() -> bool:
    """Optional @SpamBot probe — off by default (too many false positives)."""
    return os.environ.get("TELEGRAM_SPAMBOT_FROZEN_CHECK", "0").strip().lower() not in (
        "0",
        "false",
        "no",
        "off",
    )


def _system_status_notify_enabled(status: str) -> bool:
    """Telegram System Status alerts per status type."""
    st = str(status or "").strip()
    if st == "Frozen":
        return os.environ.get("TELEGRAM_NOTIFY_FROZEN", "0").strip().lower() in (
            "1",
            "true",
            "yes",
            "on",
        )
    if st == "Expired":
        return os.environ.get("TELEGRAM_NOTIFY_EXPIRED", "1").strip().lower() not in (
            "0",
            "false",
            "no",
            "off",
        )
    return True


def _spambot_probe_timeout_sec() -> float:
    return float(_env_int("TELEGRAM_SPAMBOT_PROBE_TIMEOUT_SEC", 4, minimum=2))


def classify_spambot_reply(text: str) -> bool | None:
    """
    Parse @SpamBot reply.
    True=full account frozen, False=active or soft spam limit, None=unknown.
    """
    t = str(text or "").strip().lower()
    if not t or t == "/start":
        return None
    if any(p in t for p in _SPAMBOT_OK_PHRASES):
        return False
    if any(p in t for p in _SPAMBOT_FROZEN_PHRASES):
        return True
    if any(p in t for p in _SPAMBOT_SOFT_LIMIT_PHRASES):
        return False
    return None


async def _fetch_spambot_reply_text(client: TelegramClient) -> str:
    """Send /start and return the first incoming @SpamBot reply (skip our outgoing message)."""
    start_id: int | None = None
    try:
        sent = await client.send_message(SPAMBOT_PEER, "/start")
        start_id = int(getattr(sent, "id", 0) or 0) or None
    except Exception:
        return ""
    deadline = time.monotonic() + _spambot_probe_timeout_sec()
    while time.monotonic() < deadline:
        await asyncio.sleep(0.4)
        try:
            msgs = await client.get_messages(SPAMBOT_PEER, limit=8)
        except Exception:
            continue
        for msg in msgs:
            if getattr(msg, "out", False):
                continue
            txt = str(getattr(msg, "message", None) or "").strip()
            if not txt:
                continue
            mid = int(getattr(msg, "id", 0) or 0)
            if start_id is not None and mid <= start_id:
                continue
            return txt
    return ""


async def probe_spambot_frozen(client: TelegramClient) -> bool | None:
    """True=full spam freeze, False=clear/soft-limit, None=unknown (keep Active)."""
    try:
        text = await _fetch_spambot_reply_text(client)
        if not text:
            return None
        return classify_spambot_reply(text)
    except Exception as e:
        logger.debug("spambot probe failed: %s", e)
        return None


def sync_probe_spambot_frozen(client: TelegramClient) -> bool | None:
    """Sync wrapper for health-check (temp Telethon client)."""
    try:
        if client.is_connected():
            return client.loop.run_until_complete(probe_spambot_frozen(client))
    except Exception as e:
        logger.debug("sync spambot probe failed: %s", e)
    return None


def _apply_listen_profile_update(
    acc: dict[str, Any],
    profile_name: str,
    *,
    list_key: str,
    json_path: Path,
    tag: str,
) -> None:
    """Write Telegram display name to JSON when Telethon pushes a profile update."""
    acc_id = str(acc.get("id") or "").strip()
    hint = profile_name.strip()
    if not acc_id or not hint:
        return
    old_hint = str(acc.get("profile_hint") or "").strip()
    acc["detected_profile"] = hint
    if hint == old_hint:
        return
    if update_json_profile_hint(json_path, list_key, acc_id, hint):
        acc["profile_hint"] = hint
        print(f"  [{tag}] {acc_id} profile → {hint}", flush=True)


def _register_listen_profile_handlers(
    client: TelegramClient,
    acc: dict[str, Any],
    *,
    me_id: int,
    list_key: str,
    json_path: Path,
    tag: str,
) -> None:
    """Detect own display-name changes via Telethon updates (no polling)."""

    @client.on(events.Raw)
    async def profile_raw_handler(update: Any, _acc=acc, _tag=tag, _me_id=me_id) -> None:
        try:
            if not isinstance(update, UpdateUserName):
                return
            if update.user_id != _me_id:
                return
            profile_name = profile_name_from_me(update, str(_acc.get("id") or ""))
            if not profile_name:
                return
            _apply_listen_profile_update(
                _acc,
                profile_name,
                list_key=list_key,
                json_path=json_path,
                tag=_tag,
            )
        except Exception as e:
            logger.debug("[%s] profile update handler: %s", _tag, e)


def update_json_profile_hint(path: Path, list_key: str, account_id: str, profile_hint: str) -> bool:
    aid = account_id.strip()
    hint = profile_hint.strip()
    if not aid or not hint:
        return False

    def writer(data: dict[str, Any]) -> None:
        rows = data.get(list_key)
        if not isinstance(rows, list):
            return
        for row in rows:
            if isinstance(row, dict) and str(row.get("id", "")).strip() == aid:
                row["profile_hint"] = hint
                return

    return _mutate_json_file(path, writer)


def _json_path_for_list_key(list_key: str) -> Path:
    if list_key == "shooter_accounts":
        return shooter_accounts_json_path()
    return accounts_json_path()


def sync_profiles_to_json(accounts: list[dict[str, Any]], list_key: str) -> int:
    """Connect session yang ada, baca get_me(), tulis profile_hint ke JSON."""
    path = _json_path_for_list_key(list_key)
    conn_retries = _env_int("TELETHON_CONNECTION_RETRIES", 5, minimum=1)
    req_retries = _env_int("TELETHON_REQUEST_RETRIES", 5, minimum=1)
    updated = 0
    for acc in accounts:
        acc_id = str(acc.get("id") or "?")
        session_path: Path = acc["session"]
        session_file = (
            Path(str(session_path) + ".session")
            if not str(session_path).endswith(".session")
            else session_path
        )
        if not session_file.is_file() or session_file.stat().st_size < 1024:
            print(f"  ⏭ {acc_id} — no session, skip sync")
            continue
        client = TelegramClient(
            str(session_path),
            acc["api_id"],
            acc["api_hash"],
            device_model="FRIDAY_BO",
            connection_retries=conn_retries,
            request_retries=req_retries,
        )
        try:
            client.loop.run_until_complete(client.connect())
            if not client.loop.run_until_complete(client.is_user_authorized()):
                cmd = "login-all-shooter" if list_key == "shooter_accounts" else "login-all"
                print(f"  ⏭ {acc_id} — session expired, run {cmd}")
                continue
            me = client.loop.run_until_complete(client.get_me())
            if not me:
                print(f"  ✗ {acc_id} — get_me() empty")
                continue
            name = profile_name_from_me(me, acc_id)
            if update_json_profile_hint(path, list_key, acc_id, name):
                print(f"  ✓ {acc_id} → {name}", flush=True)
                updated += 1
            else:
                print(f"  ✗ {acc_id} — failed to write JSON")
        except Exception as e:
            print(f"  ✗ {acc_id} — {type(e).__name__}: {e}")
        finally:
            try:
                if client.is_connected():
                    client.loop.run_until_complete(client.disconnect())
            except Exception:
                pass
        time.sleep(0.15)
    return updated


def list_shooter_owners(raw: dict[str, Any], shooter_rows: list[dict[str, Any]]) -> list[str]:
    configured = raw.get("shooter_users")
    if isinstance(configured, list) and configured:
        owners = {str(x).strip().upper() for x in configured if str(x).strip()}
    else:
        owners = {str(r.get("owner") or "").strip().upper() for r in shooter_rows if r.get("owner")}
    return sorted(owners)


def filter_shooter_by_owner(shooter_rows: list[dict[str, Any]], owner: str) -> list[dict[str, Any]]:
    key = owner.strip().upper()
    return [r for r in shooter_rows if str(r.get("owner") or "").strip().upper() == key]


def filter_shooter_by_currency(shooter_rows: list[dict[str, Any]], currency: str) -> list[dict[str, Any]]:
    key = str(currency or "").strip().upper()
    if not key:
        return shooter_rows
    return [
        r
        for r in shooter_rows
        if str(r.get("currency") or SHOOTER_DEFAULT_CURRENCY).strip().upper() == key
    ]


def shooter_row_has_brand(row: dict[str, Any]) -> bool:
    return bool(str(row.get("brand") or "").strip())


def shooter_rows_have_brand(rows: list[dict[str, Any]]) -> bool:
    return any(shooter_row_has_brand(r) for r in rows)


def group_shooter_rows_by_brand(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Only rows with brand field; rows without brand are excluded."""
    by: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        if not shooter_row_has_brand(row):
            continue
        b = str(row.get("brand") or "").strip().upper()
        by.setdefault(b, []).append(row)
    for b in by:
        by[b].sort(key=lambda r: (str(r.get("profile_hint") or r.get("id") or "")).lower())
    return dict(sorted(by.items(), key=lambda kv: kv[0].lower()))


def format_shooter_account_line(row: dict[str, Any], index: int) -> str:
    phone = html.escape(str(row.get("phone") or "-").strip())
    name = str(row.get("profile_hint") or "").strip()
    if name:
        label = html.escape(name)
    else:
        label = "<i>(profile after login-all-shooter)</i>"
    return f"<b>{index}.</b> <code>{phone}</code>  ·  {label}"


_COUNTRY_TO_CURRENCY: dict[str, str] = {
    "MY": "MYR", "ID": "IDR", "TH": "THB", "VN": "VND",
    "PH": "PHP", "SG": "SGD", "KH": "KHR", "IN": "INR",
    "CN": "CNY", "JP": "JPY", "KR": "KRW", "MM": "MMK",
    "BR": "BRL", "US": "USD",
}


def load_brands_config(raw: dict[str, Any]) -> dict[str, dict[str, Any]]:
    brands = raw.get("brands")
    if not isinstance(brands, dict):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for k, v in brands.items():
        if isinstance(v, dict):
            out[str(k).strip().upper()] = v
    return out


def derive_brand_currency(brand: str, brands_cfg: dict[str, dict[str, Any]]) -> str:
    b = brand.strip().upper()
    cfg = brands_cfg.get(b)
    if cfg:
        c = str(cfg.get("currency") or "").strip().upper()
        if c:
            return c
    if len(b) >= 4:
        suffix = b[-2:]
        if suffix in _COUNTRY_TO_CURRENCY:
            return _COUNTRY_TO_CURRENCY[suffix]
    return "—"


def _forum_thread_to_currency(accounts_doc: dict[str, Any], chat_id: int, thread_id: int) -> str | None:
    """Reverse lookup: given a forum chat + thread_id, return the currency name or None."""
    forum = accounts_doc.get("forum")
    if not isinstance(forum, dict):
        return None
    if str(forum.get("chat_id") or "").strip() != str(chat_id):
        return None
    topics = forum.get("topics")
    if not isinstance(topics, dict):
        return None
    for curr, cfg in topics.items():
        if isinstance(cfg, dict) and to_int(cfg.get("thread_id")) == thread_id:
            return curr
    return None


def validate_forum_topic(
    chat_id: int,
    thread_id: int | None,
    account_currency: str,
    accounts_doc: dict[str, Any],
) -> str | None:
    """Return warning message if account doesn't belong to this topic, None if OK."""
    if not thread_id:
        return None
    topic_currency = _forum_thread_to_currency(accounts_doc, chat_id, thread_id)
    if topic_currency is None:
        return None
    if account_currency.upper() == topic_currency.upper():
        return None
    return build_forum_topic_error_html(topic_currency, account_currency)


def resolve_forum_target_by_currency(
    accounts_doc: dict[str, Any], currency: str
) -> tuple[str, int] | None:
    """Return (chat_id, thread_id) for a currency forum topic, or None."""
    forum = accounts_doc.get("forum")
    if not isinstance(forum, dict):
        return None
    forum_chat_id = str(forum.get("chat_id") or "").strip()
    if not forum_chat_id:
        return None
    topics = forum.get("topics")
    if not isinstance(topics, dict):
        return None
    topic = topics.get(currency.strip().upper())
    if not isinstance(topic, dict):
        return None
    thread_id = to_int(topic.get("thread_id"))
    if not thread_id:
        return None
    return (forum_chat_id, thread_id)


def resolve_forum_target(
    accounts_doc: dict[str, Any],
    acc: dict[str, Any],
    brands_cfg: dict[str, dict[str, Any]],
) -> tuple[str, int] | None:
    """Return (chat_id, thread_id) for this account's currency forum topic, or None."""
    currency = account_currency_for_request(acc, brands_cfg)
    return resolve_forum_target_by_currency(accounts_doc, currency)


def build_otp_send_targets(
    accounts_doc: dict[str, Any],
    acc: dict[str, Any],
    brands_cfg: dict[str, dict[str, Any]],
    req: dict[str, Any] | None,
) -> list[tuple[str, int | None]]:
    """
    OTP hanya ke tempat request (/login).
    Tanpa request aktif: fallback ke forum topic currency saja (bukan DM personal staff).
    """
    if req:
        req_chat = str(req.get("requester_chat_id") or "").strip()
        req_thread = to_int(req.get("requester_thread_id"))
        if req_chat:
            return [(req_chat, req_thread)]

    send_targets: list[tuple[str, int | None]] = []
    forum_target = resolve_forum_target(accounts_doc, acc, brands_cfg)
    if forum_target:
        send_targets.append(forum_target)
    return send_targets


def _looks_like_phone(value: str) -> bool:
    return len(normalize_phone_number(value)) >= 8


def _looks_like_shooter_id(value: str) -> bool:
    return str(value or "").strip().upper().startswith("SH_")


def get_otp_account_by_id_exact(account_id: str) -> dict[str, Any] | None:
    """Match id persis di otp_accounts (accounts.json) — tanpa fuzzy."""
    raw = load_json(accounts_json_path())
    default_peers = parse_peer_ids(os.environ.get("TELEGRAM_OTP_PEER_IDS", "777000"), [777000])
    rows = load_otp_accounts(raw, project_root(), default_peers)
    q = account_id.strip().lower()
    for row in rows:
        if str(row.get("id", "")).strip().lower() == q:
            return row
    return None


def get_otp_account_by_id(account_id: str) -> dict[str, Any] | None:
    row = get_otp_account_by_id_exact(account_id)
    if row:
        return row
    raw = load_json(accounts_json_path())
    default_peers = parse_peer_ids(os.environ.get("TELEGRAM_OTP_PEER_IDS", "777000"), [777000])
    rows = load_otp_accounts(raw, project_root(), default_peers)
    q = account_id.strip().lower()
    try:
        cutoff = float(str(os.environ.get("TELEGRAM_FUZZY_ID_CUTOFF", "0.82") or "0.82").strip())
    except ValueError:
        cutoff = 0.82
    if not (0.3 <= cutoff <= 1.0):
        cutoff = 0.82
    if os.environ.get("TELEGRAM_FUZZY_ID_MATCH", "0").strip().lower() not in ("1", "true", "yes", "on"):
        return None
    by_lid: dict[str, dict[str, Any]] = {}
    for row in rows:
        lid = str(row.get("id", "")).strip().lower()
        if lid:
            by_lid[lid] = row
    if not by_lid:
        return None
    matches = difflib.get_close_matches(q, list(by_lid.keys()), n=1, cutoff=cutoff)
    if matches:
        return by_lid[matches[0]]
    return None


def get_otp_account_by_phone(phone: str) -> dict[str, Any] | None:
    raw = load_json(accounts_json_path())
    default_peers = parse_peer_ids(os.environ.get("TELEGRAM_OTP_PEER_IDS", "777000"), [777000])
    rows = load_otp_accounts(raw, project_root(), default_peers)
    target = normalize_phone_number(phone)
    if not target:
        return None
    for row in rows:
        p = normalize_phone_number(str(row.get("phone") or ""))
        if not p:
            continue
        if p == target or p.endswith(target) or target.endswith(p):
            return row
    return None


def _shooter_login_rows() -> list[dict[str, Any]]:
    raw = load_shooter_doc()
    default_peers = parse_peer_ids(os.environ.get("TELEGRAM_OTP_PEER_IDS", "777000"), [777000])
    return load_shooter_login_accounts(raw, project_root(), default_peers)


def get_shooter_listen_account_by_id(account_id: str) -> dict[str, Any] | None:
    q = account_id.strip().lower()
    for row in _shooter_login_rows():
        if str(row.get("id", "")).strip().lower() == q:
            return row
    return None


def get_shooter_listen_account_by_phone(phone: str) -> dict[str, Any] | None:
    target = normalize_phone_number(phone)
    if not target:
        return None
    for row in _shooter_login_rows():
        p = normalize_phone_number(str(row.get("phone") or ""))
        if not p:
            continue
        if p == target or p.endswith(target) or target.endswith(p):
            return row
    return None


def get_shooter_listen_account_by_owner(owner: str) -> dict[str, Any] | None:
    """Unique owner only (single account); if >1 account return None."""
    key = owner.strip().upper()
    if not key:
        return None
    matches = [
        r
        for r in _shooter_login_rows()
        if str(r.get("owner") or "").strip().upper() == key
    ]
    if len(matches) == 1:
        return matches[0]
    return None


def resolve_listen_account(account_key: str) -> dict[str, Any] | None:
    """
    Find account for /login & listener.
    Shooter → shooteraccounts.json (id SH_* / phone / owner unik).
    GCS → accounts.json (id / phone).
    """
    key = account_key.strip()
    if not key:
        return None

    if _looks_like_shooter_id(key):
        return get_shooter_listen_account_by_id(key)

    if _looks_like_phone(key):
        row = get_shooter_listen_account_by_phone(key)
        if row:
            return row
        return get_otp_account_by_phone(key)

    row = get_shooter_listen_account_by_id(key)
    if row:
        return row

    row = get_shooter_listen_account_by_owner(key)
    if row:
        return row

    row = get_otp_account_by_id_exact(key)
    if row:
        return row

    row = get_otp_account_by_id(key)
    if row:
        return row

    return None


def find_shooter_account_from_template(rows: dict[str, str]) -> dict[str, Any] | None:
    candidates = _shooter_login_rows()
    if not candidates:
        return None
    num = normalize_phone_number(str(rows.get("account_number") or "").strip())
    if num:
        for row in candidates:
            phone = normalize_phone_number(str(row.get("phone") or ""))
            if phone and (phone == num or phone.endswith(num) or num.endswith(phone)):
                return row
    name = str(rows.get("account_name") or "").strip().lower()
    if name:
        for row in candidates:
            rid = str(row.get("id") or "").strip().lower()
            hint = str(row.get("profile_hint") or "").strip().lower()
            owner = str(row.get("owner") or "").strip().lower()
            if rid == name or name in rid or (hint and (hint == name or name in hint)):
                return row
            if owner and owner == name:
                return row
    user = str(rows.get("user") or "").strip().upper()
    if user:
        for row in candidates:
            if str(row.get("owner") or "").strip().upper() == user:
                return row
    return None


def find_listen_account_from_template(rows: dict[str, str]) -> dict[str, Any] | None:
    """Shooter (shooteraccounts.json) dicek sebelum GCS (accounts.json)."""
    num = normalize_phone_number(str(rows.get("account_number") or "").strip())
    if num:
        for row in _shooter_login_rows():
            phone = normalize_phone_number(str(row.get("phone") or ""))
            if phone and (phone == num or phone.endswith(num) or num.endswith(phone)):
                return row
        row = get_otp_account_by_phone(str(rows.get("account_number") or ""))
        if row:
            return row
    row = find_shooter_account_from_template(rows)
    if row:
        return row
    return find_otp_account_from_template(rows)


def normalize_phone_number(s: str) -> str:
    return "".join(ch for ch in (s or "") if ch.isdigit())


def _canonical_template_key(raw_key: str) -> str:
    k = raw_key.strip().lower().replace(" ", "_").replace("-", "_")
    for canonical, aliases in _TEMPLATE_KEY_ALIASES.items():
        if k == canonical or k in aliases:
            return canonical
    return k


def parse_login_template(text: str) -> dict[str, str] | None:
    """
    Parse template bebas, contoh:
    Brand : STMY
    - Channel : TG
    - Account Type : GCS
    - Account Name : xx
    - Account Number : xx
    - Remark: Help scan
    - User: Widya
    """
    if not (text or "").strip():
        return None
    rows: dict[str, str] = {}
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        s = s.lstrip("-").strip()
        if ":" not in s:
            continue
        k, v = s.split(":", 1)
        key = _canonical_template_key(k)
        rows[key] = v.strip()
    # anggap template valid jika minimal punya account_name / account_number
    if "account_name" in rows or "account_number" in rows:
        return rows
    return None


def find_otp_account_from_template(rows: dict[str, str]) -> dict[str, Any] | None:
    raw = load_json(accounts_json_path())
    default_peers = parse_peer_ids(os.environ.get("TELEGRAM_OTP_PEER_IDS", "777000"), [777000])
    candidates = load_otp_accounts(raw, project_root(), default_peers)
    if not candidates:
        return None

    name = str(rows.get("account_name") or "").strip().lower()
    num = normalize_phone_number(str(rows.get("account_number") or "").strip())

    # Prioritas 1: match nomor
    if num:
        for row in candidates:
            phone = normalize_phone_number(str(row.get("phone") or ""))
            if phone and (phone == num or phone.endswith(num) or num.endswith(phone)):
                return row
    # Prioritas 2: brand vs profile_hint / id
    brand = str(rows.get("brand") or "").strip().lower()
    if brand:
        for row in candidates:
            rid = str(row.get("id") or "").strip().lower()
            hint = str(row.get("profile_hint") or "").strip().lower()
            if hint and (hint == brand or brand in hint or hint in brand):
                return row
            if rid and (rid == brand or brand in rid or rid in brand):
                return row
    # Prioritas 3: match nama/id
    if name:
        for row in candidates:
            rid = str(row.get("id") or "").strip().lower()
            hint = str(row.get("profile_hint") or "").strip().lower()
            if rid == name or name in rid or (hint and (hint == name or name in hint)):
                return row
    return None


def set_login_request(
    account_id: str,
    requester_chat_id: str,
    target_phone: str | None,
    requester_thread_id: int | None = None,
) -> None:
    path = state_json_path()

    def writer(data: dict[str, Any]) -> None:
        reqs = data.get("login_requests")
        if not isinstance(reqs, dict):
            reqs = {}
        entry: dict[str, Any] = {
            "requester_chat_id": str(requester_chat_id),
            "target_phone": target_phone or "",
            "requested_at": datetime.now(timezone.utc).isoformat(),
        }
        if requester_thread_id:
            entry["requester_thread_id"] = requester_thread_id
        reqs[account_id] = entry
        data["login_requests"] = reqs
        data.pop("login_request", None)

    if not _mutate_json_file(path, writer):
        logger.warning("set_login_request failed: %s", path)


def get_active_login_request(account_id: str) -> dict[str, Any] | None:
    path = state_json_path()
    try:
        with _json_lock(path):
            data = load_json(path)
    except FileLockTimeout:
        logger.warning("Timeout lock get_active_login_request")
        return None
    reqs = data.get("login_requests")
    if not isinstance(reqs, dict):
        old = data.get("login_request")
        if isinstance(old, dict) and str(old.get("account_id") or "").strip().lower() == account_id.strip().lower():
            reqs = {account_id: old}
        else:
            return None
    req = reqs.get(account_id)
    if not isinstance(req, dict):
        return None
    chat = str(req.get("requester_chat_id") or "").strip()
    ts = str(req.get("requested_at") or "").strip()
    if not chat or not ts:
        return None
    ttl_sec = _env_int("TELEGRAM_LOGIN_REQUEST_TTL_SEC", 300, minimum=30)
    try:
        req_time = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    age = (datetime.now(timezone.utc) - req_time).total_seconds()
    if age > ttl_sec:
        return None
    return req


def clear_login_request(account_id: str) -> None:
    path = state_json_path()

    def writer(data: dict[str, Any]) -> None:
        reqs = data.get("login_requests")
        if isinstance(reqs, dict):
            reqs.pop(account_id, None)
            data["login_requests"] = reqs
        data.pop("login_request", None)

    if not _mutate_json_file(path, writer):
        logger.warning("clear_login_request failed: %s", path)


def account_id_from_user(user) -> str:
    return user.username if user.username else f"user_{user.id}"


def creator_account_id() -> str:
    return os.environ.get("TELEGRAM_CREATOR_ACCOUNT_ID", "geri_work").strip().lower()


def is_primary_creator_user(user: Any) -> bool:
    """Hanya akun utama (default geri_work) — bukan admin staff lain."""
    if not user:
        return False
    if account_id_from_user(user).strip().lower() == creator_account_id():
        return True
    tg_id = str(getattr(user, "id", "") or "").strip()
    uname = (getattr(user, "username", None) or "").strip().lower().lstrip("@")
    if not tg_id and not uname:
        return False
    try:
        for row in load_json(accounts_json_path()).get("accounts", []):
            if not isinstance(row, dict):
                continue
            if str(row.get("id", "")).strip().lower() != creator_account_id():
                continue
            if tg_id and str(row.get("telegram_user_id") or row.get("chat_id") or "").strip() == tg_id:
                return True
            if uname and uname in _row_telegram_usernames(row):
                return True
    except Exception:
        pass
    return False


def _find_staff_row_by_admin_hint(hint: str) -> dict[str, Any] | None:
    raw = str(hint or "").strip()
    if not raw:
        return None
    key = raw.lstrip("@").lower()
    key_u = raw.upper()
    rows = load_json(accounts_json_path()).get("accounts") or []
    for row in rows:
        if isinstance(row, dict) and str(row.get("id", "")).strip().lower() == key:
            return row
    if raw.isdigit():
        for row in rows:
            if not isinstance(row, dict):
                continue
            if str(row.get("telegram_user_id", "")).strip() == raw:
                return row
            if str(row.get("chat_id", "")).strip() == raw:
                return row
    for row in rows:
        if not isinstance(row, dict):
            continue
        if key in _row_telegram_usernames(row):
            return row
        if str(row.get("telegram_username", "")).strip().lower().lstrip("@") == key:
            return row
    for row in rows:
        if not isinstance(row, dict):
            continue
        if str(row.get("shooter_owner", "")).strip().upper() == key_u:
            return row
        if str(row.get("label", "")).strip().upper() == key_u:
            return row
    return None


def _staff_row_is_admin(row: dict[str, Any]) -> bool:
    role = str(row.get("role") or "").strip().lower()
    if role in ("admin", "creator"):
        return True
    return str(row.get("is_admin", "")).strip().lower() in ("1", "true", "yes", "on")


def promote_staff_to_admin(hint: str) -> tuple[bool, str]:
    """Promote staff yang sudah ada di accounts.json → role admin."""
    row = _find_staff_row_by_admin_hint(hint)
    if not row:
        return False, (
            accounts_header_html("⚠️ <b>Not Found</b>")
            + "\n\nStaff member not found on the staff list.\n"
            + "Add them to the staff list first, then ask them to register via <code>/start</code>."
        )
    target_id = str(row.get("id", "")).strip().lower()
    if target_id == creator_account_id():
        return True, (
            accounts_header_html("ℹ️ <b>Creator</b>")
            + f"\n\n<code>{html.escape(creator_account_id())}</code> sudah owner bot."
        )
    if _staff_row_is_admin(row):
        label = str(row.get("label") or target_id)
        return True, (
            accounts_header_html("ℹ️ <b>Already Admin</b>")
            + f"\n\n<code>{html.escape(target_id)}</code> ({html.escape(label)}) sudah admin."
        )

    result_id = target_id
    result_label = str(row.get("label") or target_id)
    result_owner = str(row.get("shooter_owner") or "")

    def writer(data: dict[str, Any]) -> None:
        nonlocal result_id, result_label, result_owner
        rows = data.get("accounts")
        if not isinstance(rows, list):
            return
        for matched in rows:
            if not isinstance(matched, dict):
                continue
            if str(matched.get("id", "")).strip().lower() != target_id:
                continue
            matched["role"] = "admin"
            result_id = str(matched.get("id") or result_id).strip()
            result_label = str(matched.get("label") or result_label).strip()
            result_owner = str(matched.get("shooter_owner") or "").strip()
            return

    if not _mutate_json_file(accounts_json_path(), writer):
        return False, accounts_header_html("⚠️ <b>Error</b>") + "\n\nCould not update staff record. Please try again."

    lines = [
        accounts_header_html("✅ <b>Admin Added</b>"),
        "",
        f"<b>id</b>     ·  <code>{html.escape(result_id)}</code>",
        f"<b>label</b>  ·  <b>{html.escape(result_label)}</b>",
        f"<b>role</b>   ·  <code>admin</code>",
    ]
    if result_owner:
        lines.append(f"<b>shooter</b> ·  <code>{html.escape(result_owner.upper())}</code>")
    lines.append("")
    lines.append("<i>No restart needed.</i>")
    return True, "\n".join(lines)


def remove_staff_admin(hint: str) -> tuple[bool, str]:
    """Cabut role admin — slot staff + shooter_owner tetap (daftar /start tetap jalan)."""
    row = _find_staff_row_by_admin_hint(hint)
    if not row:
        return False, (
            accounts_header_html("⚠️ <b>Not Found</b>")
            + "\n\nStaff not found. Try staff name, @username, or Telegram user ID."
        )
    target_id = str(row.get("id", "")).strip().lower()
    if target_id == creator_account_id():
        return False, (
            accounts_header_html("⛔ <b>Blocked</b>")
            + "\n\nThe bot owner account cannot be removed."
        )
    if not _staff_row_is_admin(row):
        label = str(row.get("label") or target_id)
        return True, (
            accounts_header_html("ℹ️ <b>Not Admin</b>")
            + f"\n\n<code>{html.escape(target_id)}</code> ({html.escape(label)}) bukan admin."
        )

    result_id = target_id
    result_label = str(row.get("label") or target_id)
    result_owner = str(row.get("shooter_owner") or "")

    def writer(data: dict[str, Any]) -> None:
        nonlocal result_id, result_label, result_owner
        rows = data.get("accounts")
        if not isinstance(rows, list):
            return
        for matched in rows:
            if not isinstance(matched, dict):
                continue
            if str(matched.get("id", "")).strip().lower() != target_id:
                continue
            matched.pop("role", None)
            matched.pop("is_admin", None)
            result_id = str(matched.get("id") or result_id).strip()
            result_label = str(matched.get("label") or result_label).strip()
            result_owner = str(matched.get("shooter_owner") or "").strip()
            return

    if not _mutate_json_file(accounts_json_path(), writer):
        return False, accounts_header_html("⚠️ <b>Error</b>") + "\n\nCould not update staff record. Please try again."

    lines = [
        accounts_header_html("✅ <b>Admin Removed</b>"),
        "",
        f"<b>id</b>     ·  <code>{html.escape(result_id)}</code>",
        f"<b>label</b>  ·  <b>{html.escape(result_label)}</b>",
    ]
    if result_owner:
        lines.append(f"<b>shooter</b> ·  <code>{html.escape(result_owner.upper())}</code> (tetap)")
    lines.append("")
    lines.append("<i>Shooter /start &amp; /other tetap jalan — no restart needed.</i>")
    return True, "\n".join(lines)


def build_staff_admin_usage_html() -> str:
    return (
        accounts_header_html("ℹ️ <b>Staff Admin</b>")
        + "\n\n"
        + "<b>Usage (bot owner only):</b>\n"
        + "◦ <code>/add admin jun</code>\n"
        + "◦ <code>/add admin @JunWork16</code>\n"
        + "◦ <code>/remove jun</code>\n"
        + "◦ <code>/remove @JunWork16</code>\n\n"
        + "<i>Staff must already be on the staff list (registered via <code>/start</code>). "
        + "This command only grants or removes admin role.</i>"
    )


def _require_primary_creator(update: Update) -> bool:
    user = update.effective_user
    return bool(user and is_primary_creator_user(user))


async def _reply_creator_only(em: Any) -> None:
    await em.reply_text(
        accounts_header_html("⛔ <b>Access Denied</b>")
        + "\n\nThis command is for the <b>bot owner</b> only.",
        parse_mode="HTML",
    )


async def cmd_add(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    em = update.effective_message
    if not em:
        return
    if not _require_primary_creator(update):
        await _reply_creator_only(em)
        return
    args = [str(a).strip() for a in (context.args or []) if str(a).strip()]
    if len(args) != 2 or args[0].lower() != "admin" or not args[1]:
        await em.reply_text(build_staff_admin_usage_html(), parse_mode="HTML")
        return
    _, msg = promote_staff_to_admin(args[1])
    await em.reply_text(msg, parse_mode="HTML")


async def cmd_remove(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    em = update.effective_message
    if not em:
        return
    if not _require_primary_creator(update):
        await _reply_creator_only(em)
        return
    hint = " ".join(context.args or []).strip()
    if not hint:
        await em.reply_text(build_staff_admin_usage_html(), parse_mode="HTML")
        return
    _, msg = remove_staff_admin(hint)
    await em.reply_text(msg, parse_mode="HTML")


def is_creator_user(user: Any) -> bool:
    if not user:
        return False
    if account_id_from_user(user).strip().lower() == creator_account_id():
        return True
    tg_id = str(getattr(user, "id", "") or "").strip()
    uname = (getattr(user, "username", None) or "").strip().lower().lstrip("@")
    if not tg_id and not uname:
        return False
    try:
        for row in load_json(accounts_json_path()).get("accounts", []):
            if not isinstance(row, dict) or not _staff_row_is_admin(row):
                continue
            if tg_id and str(row.get("telegram_user_id") or "").strip() == tg_id:
                return True
            if uname and uname in _row_telegram_usernames(row):
                return True
            if uname and uname == str(row.get("id") or "").strip().lower():
                return True
    except Exception:
        pass
    return False


def creator_chat_ids() -> set[str]:
    ids: set[str] = set()
    for raw in (
        os.environ.get("TELEGRAM_CREATOR_CHAT_ID", "").strip(),
        os.environ.get("TELEGRAM_LOGIN_STATUS_CHAT_ID", "").strip(),
    ):
        for part in raw.split(","):
            p = part.strip()
            if p:
                ids.add(p)
    try:
        doc = load_json(accounts_json_path())
        for row in doc.get("accounts", []):
            if not isinstance(row, dict):
                continue
            if str(row.get("id", "")).strip().lower() == creator_account_id():
                cid = str(row.get("chat_id", "")).strip()
                if cid:
                    ids.add(cid)
            elif _staff_row_is_admin(row):
                cid = str(row.get("chat_id", "")).strip()
                if cid:
                    ids.add(cid)
    except Exception:
        pass
    return ids


def validate_otp_request_context(update: Update) -> str | None:
    """
    Return HTML error message if request is not allowed.
    Staff: hanya group/supergroup (channel). Creator: boleh private DM juga.
    """
    chat = update.effective_chat
    user = update.effective_user
    if not chat:
        return accounts_header_html("⚠️ <b>Error</b>") + "\n\nInvalid chat."
    if chat.type == ChatType.PRIVATE:
        if is_creator_user(user):
            return None
        return (
            accounts_header_html("⛔ <b>Private Blocked</b>")
            + "\n\n"
            + "OTP requests must be sent in the <b>group channel</b> (correct currency topic).\n"
            + "Private chat is not used for account requests.\n\n"
            + "<i>To register, send</i> <code>/start</code> <i>in this private chat.</i>"
        )
    if chat.type in (ChatType.GROUP, ChatType.SUPERGROUP):
        return None
    return accounts_header_html("⚠️ <b>Not Allowed</b>") + "\n\nUse the forum group channel."


def build_staff_dm_closed_html(*, topic_currency: str | None = None) -> str:
    return (
        accounts_header_html("🔒 <b>DM — /start only</b>")
        + "\n\n"
        + "In bot private DM, staff may only use <code>/start</code> (registration).\n"
        + group_channel_topic_hint(topic_currency=topic_currency)
        + "\n\n<i>/start in the group/topic has no effect.</i>"
    )


async def guard_staff_private_dm(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Staff (bukan geri_work): di DM hanya boleh /start → cmd_start.
    Perintah lain di DM diblokir. Creator bebas semua perintah di DM.
    """
    chat = update.effective_chat
    if not chat or chat.type != ChatType.PRIVATE:
        return
    user = update.effective_user
    if is_creator_user(user):
        return
    em = update.effective_message
    if not em:
        raise ApplicationHandlerStop()

    text = (em.text or em.caption or "").strip()
    first = text.split()[0].split("@")[0].lower() if text else ""
    if first == "/start":
        return
    if first in ("/add", "/remove") and is_primary_creator_user(user):
        return

    staff = resolve_requester_staff(user)
    if staff is None:
        await em.reply_text(
            accounts_header_html("ℹ️ <b>Registration</b>")
            + "\n\n"
            + "Only <code>/start</code> is allowed in <b>bot DM</b> (not in group/topic).\n"
            + "After ✅ Registered, use <code>/other</code> and <code>/login</code> in the group channel.",
            parse_mode="HTML",
        )
    else:
        await em.reply_text(
            build_staff_dm_closed_html(topic_currency=topic_currency_from_update(update)),
            parse_mode="HTML",
        )
    raise ApplicationHandlerStop()


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.effective_chat or not update.effective_user or not update.effective_message:
        return
    em = update.effective_message
    cid = update.effective_chat.id
    uid = account_id_from_user(update.effective_user)
    label = (update.effective_user.full_name or uid).strip()
    thread_id = getattr(em, "message_thread_id", None)
    is_forum = getattr(update.effective_chat, "is_forum", False)
    creator = is_creator_user(update.effective_user)
    # Grup/topic: hanya owner yang dapat balasan; staff/orang lain → diam (no reply).
    if update.effective_chat.type != ChatType.PRIVATE and not creator:
        return
    name_hint = " ".join(context.args).strip() if context.args else ""
    registered = False
    allowlisted = True
    if (
        update.effective_chat.type == ChatType.PRIVATE
        and os.environ.get("TELEGRAM_AUTO_REGISTER", "1").strip().lower()
        not in ("0", "false", "no", "off")
    ):
        _, allowlisted = register_private_staff_chat(
            update.effective_user, str(cid), label, name_hint=name_hint
        )
        registered = allowlisted
    if creator:
        welcome = build_bot_welcome_html(cid, uid, thread_id, bool(is_forum and thread_id))
        if registered:
            welcome += "\n\n✅ <b>Owner registered</b> for this chat."
    elif registered and update.effective_chat.type == ChatType.PRIVATE:
        staff_row = find_staff_row_for_user(update.effective_user)
        shooter_key = resolve_shooter_owner_for_staff(
            str((staff_row or {}).get("id") or uid), staff_row
        )
        welcome = (
            "✅ <b>Registered</b>\n\n"
            + group_channel_topic_hint()
            + (
                f"\n\n<i>Your shooter user:</i> <b>{html.escape(_format_shooter_owner_label(shooter_key))}</b>"
                if shooter_key
                else ""
            )
        )
    elif update.effective_chat.type == ChatType.PRIVATE and staff_require_allowlist():
        hint_tip = (
            "\n\nTry: <code>/start YourShooterName</code>  e.g. <code>/start Vennus</code>" if not name_hint else
            "\n\nName not found in the staff list. Ask admin for your shooter name."
        )
        welcome = build_staff_not_allowlisted_html(update.effective_user) + hint_tip
    elif update.effective_chat.type != ChatType.PRIVATE:
        welcome = build_bot_welcome_html(cid, uid, thread_id, bool(is_forum and thread_id))
    else:
        welcome = accounts_header_html("🤖 <b>Bot Ready</b>") + "\n\n<i>Send /start to register.</i>"
    await em.reply_text(welcome, parse_mode="HTML")


async def cmd_accounts(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    em = update.effective_message
    chat = update.effective_chat
    if not em or not chat:
        return
    private_only = os.environ.get("TELEGRAM_ACCOUNTS_CMD_PRIVATE_ONLY", "0").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )
    if private_only and chat.type != ChatType.PRIVATE:
        await em.reply_text(
            accounts_header_html("ℹ️ <b>Private Only</b>")
            + "\n\n"
            "<code>/main</code> is disabled in groups.\n"
            "Use a private chat with this bot.",
            parse_mode="HTML",
        )
        return
    raw = load_json(accounts_json_path())
    default_peers = parse_peer_ids(os.environ.get("TELEGRAM_OTP_PEER_IDS", "777000"), [777000])
    rows = load_otp_accounts(raw, project_root(), default_peers)
    brands_cfg = load_brands_config(raw)
    rows = [r for r in rows if derive_otp_brand(r, brands_cfg) != "UNKNOWN"]
    if not rows:
        await em.reply_text(
            accounts_header_html("⚠️ <b>No Accounts</b>") + "\n\nNo active GCS accounts are available.",
            parse_mode="HTML",
        )
        return
    grouped = group_otp_rows_by_brand(rows, brands_cfg)
    brand_filter = " ".join(context.args).strip().upper() if context.args else ""
    thread_id = getattr(em, "message_thread_id", None)

    if not brand_filter and thread_id:
        topic_currency = _forum_thread_to_currency(raw, chat.id, thread_id)
        if topic_currency:
            matching = [(b, rs) for b, rs in grouped.items()
                        if derive_brand_currency(b, brands_cfg).upper() == topic_currency.upper()]
            if not matching:
                await em.reply_text(
                    accounts_header_html(f"⚠️ <b>{html.escape(topic_currency)}</b>")
                    + f"\n\nNo accounts for this topic.",
                    parse_mode="HTML",
                )
                return
            full = build_accounts_currency_topic_html(topic_currency, matching)
            await em.reply_text(full, parse_mode="HTML")
            return

    if brand_filter:
        items = [(b, rs) for b, rs in grouped.items() if b.upper() == brand_filter]
        if not items:
            await em.reply_text(
                build_accounts_brand_not_found_html(brand_filter, list(grouped.keys())),
                parse_mode="HTML",
            )
            return
        brand, rs = items[0]
        currency = derive_brand_currency(brand, brands_cfg)
        topic_err = validate_forum_topic(chat.id, thread_id, currency, raw)
        if topic_err:
            await em.reply_text(topic_err, parse_mode="HTML")
            return
        full = build_accounts_brand_detail_html(brand, currency, rs)
        if len(full) <= 4096:
            await em.reply_text(full, parse_mode="HTML")
        else:
            header = build_accounts_brand_detail_html(brand, currency, [])
            lines: list[str] = []
            for i, r in enumerate(rs, 1):
                phone = html.escape(str(r.get("phone") or "-").strip())
                name = html.escape(str(r.get("profile_hint") or r.get("id") or "-").strip())
                lines.append(f"<b>{i}.</b> <code>{phone}</code>  ·  {name}")
            await em.reply_text(header, parse_mode="HTML")
            for chunk in lines:
                await context.bot.send_message(chat_id=chat.id, text=chunk, parse_mode="HTML")
    else:
        by_currency: dict[str, list[tuple[str, list[dict[str, Any]]]]] = {}
        for brand, rs in grouped.items():
            currency = derive_brand_currency(brand, brands_cfg)
            by_currency.setdefault(currency, []).append((brand, rs))
        total = sum(len(rs) for rs in grouped.values())
        total_brands = len(grouped)
        full = build_accounts_overview_html(total, total_brands, by_currency)
        if len(full) <= 4096:
            await em.reply_text(full, parse_mode="HTML")
        else:
            header = accounts_header_html("🔐 <b>OTP Accounts Overview</b>")
            stats = f"\n\n📊 <b>{total}</b> accounts  ·  <b>{total_brands}</b> brands"
            await em.reply_text(header + stats, parse_mode="HTML")
            for currency in sorted(by_currency.keys()):
                brands_in = sorted(by_currency[currency], key=lambda x: x[0].lower())
                sec = build_accounts_currency_topic_html(currency, brands_in)
                await context.bot.send_message(chat_id=chat.id, text=sec, parse_mode="HTML")
            await context.bot.send_message(
                chat_id=chat.id,
                text="<i>/main &lt;BRAND&gt;</i>  ·  <code>/main STMY</code>",
                parse_mode="HTML",
            )


async def cmd_shooter(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Shooter accounts — /other GERI shows list for user GERI only."""
    em = update.effective_message
    chat = update.effective_chat
    if not em or not chat:
        return
    private_only = os.environ.get("TELEGRAM_ACCOUNTS_CMD_PRIVATE_ONLY", "0").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )
    if private_only and chat.type != ChatType.PRIVATE:
        await em.reply_text(
            accounts_header_html("ℹ️ <b>Private Only</b>")
            + "\n\n"
            "<code>/other</code> is disabled in groups.\n"
            "Use a private chat with this bot.",
            parse_mode="HTML",
        )
        return
    shooter_doc = load_shooter_doc()
    shooter_rows = load_shooter_accounts(shooter_doc)
    owners = list_shooter_owners(shooter_doc, shooter_rows)
    owner_filter = " ".join(context.args).strip().upper() if context.args else ""
    thread_id = getattr(em, "message_thread_id", None)
    accounts_doc = load_json(accounts_json_path())
    topic_currency = (
        _forum_thread_to_currency(accounts_doc, chat.id, thread_id) if thread_id else None
    )
    user = update.effective_user
    ensure_staff_linked(user)
    if is_creator_user(user):
        staff = "__creator__"
        staff_row = None
        staff_shooter = ""
    else:
        staff_row = find_staff_row_for_user(
            user,
            shooter_owner_hint=owner_filter,
        )
        staff = str(staff_row.get("id") or "").strip().lower() if staff_row else None
        if staff is None:
            staff = resolve_requester_staff(user)
            staff_row = find_staff_row_for_user(user)
        staff_shooter = resolve_shooter_owner_for_staff(staff, staff_row) if staff else ""
    if owner_filter:
        owner_filter = effective_shooter_owner_filter(
            staff,
            staff_row,
            staff_shooter,
            owner_filter,
            user=user,
        )

    if not owner_filter:
        if staff == "__creator__":
            list_rows = shooter_rows
        elif staff:
            user_rows = find_staff_rows_for_user(user)
            if len(user_rows) > 1:
                allowed = {
                    str(r.get("shooter_owner") or "").strip().upper()
                    for r in user_rows
                    if str(r.get("shooter_owner") or "").strip()
                }
                list_rows = [
                    r
                    for r in shooter_rows
                    if str(r.get("owner") or "").strip().upper() in allowed
                ]
            elif staff_shooter:
                list_rows = filter_shooter_by_owner(shooter_rows, staff_shooter)
            else:
                await em.reply_text(
                    build_staff_not_registered_html(
                        update.effective_user, topic_currency=topic_currency
                    ),
                    parse_mode="HTML",
                )
                return
        if topic_currency:
            list_rows = filter_shooter_by_currency(list_rows, topic_currency)
        currency = topic_currency or str(
            shooter_doc.get("shooter_currency") or SHOOTER_DEFAULT_CURRENCY
        ).strip().upper()
        if topic_currency and not list_rows:
            await em.reply_text(
                accounts_header_html(f"⚠️ <b>{html.escape(topic_currency)} Shooter</b>")
                + f"\n\nNo shooter accounts for this topic.",
                parse_mode="HTML",
            )
            return
        await em.reply_text(
            build_shooter_owners_list_html(list_rows, currency),
            parse_mode="HTML",
        )
        return

    if staff is None:
        await em.reply_text(
            build_staff_not_registered_html(
                update.effective_user, topic_currency=topic_currency
            ),
            parse_mode="HTML",
        )
        return

    matched = filter_shooter_by_owner(shooter_rows, owner_filter)
    if topic_currency:
        matched = filter_shooter_by_currency(matched, topic_currency)
    if not matched:
        if topic_currency:
            await em.reply_text(
                accounts_header_html(f"⚠️ <b>{html.escape(topic_currency)} Shooter</b>")
                + f"\n\nNo shooter accounts for <code>{html.escape(owner_filter)}</code> in this topic.",
                parse_mode="HTML",
            )
            return
        await em.reply_text(
            build_shooter_user_not_found_html(owner_filter, owners),
            parse_mode="HTML",
        )
        return

    raw = accounts_doc
    brands_cfg = load_brands_config(raw)
    full = build_shooter_user_accounts_html(owner_filter, matched, brands_cfg)
    if len(full) <= 4096:
        await em.reply_text(full, parse_mode="HTML")
    else:
        header = accounts_header_html(f"🎯 <b>Shooter · {html.escape(owner_filter)}</b>")
        await em.reply_text(header, parse_mode="HTML")
        idx = 0
        if shooter_rows_have_brand(matched):
            grouped = group_shooter_rows_by_brand(matched)
            unbranded = [r for r in matched if not shooter_row_has_brand(r)]
            for brand, brand_rows in grouped.items():
                currency = derive_brand_currency(brand, brands_cfg)
                sec_lines = [
                    f"🔹 <b>{html.escape(brand)}</b>  ·  {html.escape(currency)}",
                    "",
                ]
                for r in brand_rows:
                    idx += 1
                    sec_lines.append(format_shooter_account_line(r, idx))
                await context.bot.send_message(chat_id=chat.id, text="\n".join(sec_lines), parse_mode="HTML")
            if unbranded:
                sec_lines = ["◦ <b>Shooter accounts</b>", ""]
                for r in unbranded:
                    idx += 1
                    sec_lines.append(format_shooter_account_line(r, idx))
                await context.bot.send_message(chat_id=chat.id, text="\n".join(sec_lines), parse_mode="HTML")
        else:
            for chunk_start in range(0, len(matched), 40):
                chunk = matched[chunk_start : chunk_start + 40]
                sec_lines: list[str] = []
                for r in chunk:
                    idx += 1
                    sec_lines.append(format_shooter_account_line(r, idx))
                await context.bot.send_message(chat_id=chat.id, text="\n".join(sec_lines), parse_mode="HTML")


async def cmd_ping(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    em = update.effective_message
    if not em:
        return
    await em.reply_text(
        accounts_header_html("🏓 <b>Pong</b>") + "\n\nBot is running.",
        parse_mode="HTML",
    )


async def cmd_login(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.effective_chat or not update.effective_message:
        return
    em = update.effective_message
    if not context.args:
        await em.reply_text(
            accounts_header_html("ℹ️ <b>Login Usage</b>")
            + "\n\n"
            "<code>/login &lt;id or phone number&gt;</code>\n\n"
            "<b>GCS</b> — use the topic that matches the brand (SGD, MYR, USC, …):\n"
            "· <code>/login STMY_CS01</code>\n"
            "· <code>/login +60123456789</code>\n\n"
            f"<b>Shooter</b> — <b>{html.escape(SHOOTER_DEFAULT_CURRENCY)}</b> topic only:\n"
            "· <code>/login SH_VENAN_01</code>\n"
            "· <code>/login +60123456789</code> <i>(registered phone number)</i>",
            parse_mode="HTML",
        )
        return
    denied = validate_otp_request_context(update)
    if denied:
        await em.reply_text(denied, parse_mode="HTML")
        return
    ensure_staff_linked(update.effective_user)
    raw_key = " ".join(str(a) for a in context.args).strip()
    row = resolve_listen_account(raw_key)
    if not row:
        owner_hint = ""
        if raw_key.strip() and not _looks_like_phone(raw_key) and not _looks_like_shooter_id(raw_key):
            owner_u = raw_key.strip().upper()
            n = sum(
                1
                for r in _shooter_login_rows()
                if str(r.get("owner") or "").strip().upper() == owner_u
            )
            if n > 1:
                owner_hint = (
                    f"\n\n<code>{html.escape(owner_u)}</code> has <b>{n}</b> shooter account(s) — "
                    "use the account id (<code>SH_KAREN_05</code>) or phone number, not just the owner name."
                )
        await em.reply_text(
            accounts_header_html("⚠️ <b>Not Found</b>")
            + f"\n\n<code>{html.escape(raw_key)}</code> not found in GCS or Shooter."
            + owner_hint
            + "\n\nGCS: <code>/login STMY_CS01</code> · Shooter: <code>/login SH_KAREN_05</code> or <code>/login +60...</code>",
            parse_mode="HTML",
        )
        return
    thread_id = getattr(em, "message_thread_id", None)
    raw_doc = load_json(accounts_json_path())
    brands_cfg = load_brands_config(raw_doc)
    currency = account_currency_for_request(row, brands_cfg)
    topic_err = validate_forum_topic(update.effective_chat.id, thread_id, currency, raw_doc)
    if topic_err:
        await em.reply_text(topic_err, parse_mode="HTML")
        return
    if account_pool(row) == "shooter":
        denied_owner = validate_shooter_owner_access(
            update, str(row.get("owner") or "")
        )
        if denied_owner:
            await em.reply_text(denied_owner, parse_mode="HTML")
            return
    phone = str(row.get("phone") or "").strip() or "-"
    detected = str(row.get("profile_hint") or row.get("id") or "-")
    set_login_request(str(row["id"]), str(update.effective_chat.id), phone, thread_id)
    await em.reply_text(
        build_login_request_accepted_html(detected, phone),
        parse_mode="HTML",
    )


async def on_text_template(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.effective_chat or not update.effective_message:
        return
    # Allow template from private/group/supergroup (channels still ignored).
    if update.effective_chat.type not in (ChatType.PRIVATE, ChatType.GROUP, ChatType.SUPERGROUP):
        return
    msg = update.effective_message
    text = (msg.text or msg.caption or "").strip()

    thread_id = getattr(msg, "message_thread_id", None)
    raw_doc = load_json(accounts_json_path())
    bcfg = load_brands_config(raw_doc)

    # 1) Template multiline (Brand/Channel/Account Name/Account Number/...)
    parsed = parse_login_template(text)
    if parsed:
        denied = validate_otp_request_context(update)
        if denied:
            await msg.reply_text(denied, parse_mode="HTML")
            return
        ensure_staff_linked(update.effective_user)
        row = find_listen_account_from_template(parsed)
        if not row:
            await msg.reply_text(
                accounts_header_html("⚠️ <b>No Match</b>")
                + "\n\nTemplate detected but no matching account.\n"
                "Check Account Name / Number (GCS or Shooter).",
                parse_mode="HTML",
            )
            return
        currency = account_currency_for_request(row, bcfg)
        topic_err = validate_forum_topic(update.effective_chat.id, thread_id, currency, raw_doc)
        if topic_err:
            await msg.reply_text(topic_err, parse_mode="HTML")
            return
        if account_pool(row) == "shooter":
            denied_owner = validate_shooter_owner_access(
                update, str(row.get("owner") or "")
            )
            if denied_owner:
                await msg.reply_text(denied_owner, parse_mode="HTML")
                return
        phone = str(row.get("phone") or "").strip() or "-"
        set_login_request(str(row["id"]), str(update.effective_chat.id), phone, thread_id)
        req_user = parsed.get("user", "-")
        req_brand = parsed.get("brand", "-")
        detected = str(row.get("profile_hint") or row.get("id") or "-")
        await msg.reply_text(
            build_login_request_accepted_html(detected, phone, brand=req_brand, user=req_user),
            parse_mode="HTML",
        )
        return

    # 2) Template singkat: LOGIN <id>
    m = LOGIN_REQ_PATTERN.match(text)
    if not m:
        return
    denied = validate_otp_request_context(update)
    if denied:
        await msg.reply_text(denied, parse_mode="HTML")
        return
    ensure_staff_linked(update.effective_user)
    aid = m.group(1).strip()
    row = resolve_listen_account(aid)
    if not row:
        await msg.reply_text(
            accounts_header_html("⚠️ <b>Not Found</b>")
            + f"\n\nAccount <code>{html.escape(aid)}</code> not found (GCS / Shooter).",
            parse_mode="HTML",
        )
        return
    currency = account_currency_for_request(row, bcfg)
    topic_err = validate_forum_topic(update.effective_chat.id, thread_id, currency, raw_doc)
    if topic_err:
        await msg.reply_text(topic_err, parse_mode="HTML")
        return
    if account_pool(row) == "shooter":
        denied_owner = validate_shooter_owner_access(
            update, str(row.get("owner") or "")
        )
        if denied_owner:
            await msg.reply_text(denied_owner, parse_mode="HTML")
            return
    phone = str(row.get("phone") or "").strip() or "-"
    detected = str(row.get("profile_hint") or row.get("id") or "-")
    set_login_request(str(row["id"]), str(update.effective_chat.id), phone, thread_id)
    await msg.reply_text(
        build_login_request_accepted_html(detected, phone),
        parse_mode="HTML",
    )


async def track_private_chat(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.effective_user or not update.effective_chat:
        return
    if update.effective_chat.type != ChatType.PRIVATE:
        return
    if is_creator_user(update.effective_user):
        pass
    elif resolve_requester_staff(update.effective_user):
        return
    write_last_private_chat(
        state_json_path(),
        str(update.effective_chat.id),
        account_id_from_user(update.effective_user),
    )


async def bot_on_error(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    if isinstance(context.error, Conflict):
        logger.error("409 Conflict: only one bot instance allowed per token.")
        return
    logger.error("Error bot", exc_info=context.error)


def run_bot() -> int:
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    if not token:
        print("TELEGRAM_BOT_TOKEN is empty in .env", file=sys.stderr)
        return 2
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())
    # Cegah instance bot ganda di mesin yang sama (penyebab 409 paling umum).
    bot_lock = FileLock(str(project_root() / ".bot_polling.lock"), timeout=0)
    try:
        bot_lock.acquire()
    except FileLockTimeout:
        logger.error("Bot is already running on this machine. Stop the other instance first.")
        return 1

    app = Application.builder().token(token).build()
    app.add_handler(MessageHandler(filters.ChatType.PRIVATE, guard_staff_private_dm), group=-1)
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("add", cmd_add))
    app.add_handler(CommandHandler("remove", cmd_remove))
    app.add_handler(CommandHandler("ping", cmd_ping))
    app.add_handler(CommandHandler("main", cmd_accounts))
    app.add_handler(CommandHandler("other", cmd_shooter))
    app.add_handler(CommandHandler("login", cmd_login))
    app.add_handler(MessageHandler(filters.ChatType.PRIVATE, track_private_chat), group=1)
    app.add_handler(
        MessageHandler(
            (filters.ChatType.PRIVATE | filters.ChatType.GROUP | filters.ChatType.SUPERGROUP)
            & (filters.TEXT | filters.CAPTION)
            & ~filters.COMMAND,
            on_text_template,
        ),
        group=2,
    )
    app.add_error_handler(bot_on_error)
    try:
        logger.info("Bot polling started...")
        app.run_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=True)
        return 0
    finally:
        try:
            bot_lock.release()
        except Exception:
            pass


def run_notify(message: str, account: str | None, broadcast: bool) -> int:
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    if not token:
        print("TELEGRAM_BOT_TOKEN is empty", file=sys.stderr)
        return 2
    raw = load_json(accounts_json_path())
    try:
        targets = resolve_targets(raw, account, broadcast)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 2
    for cid in targets:
        try:
            send_message(token, cid, message)
        except Exception as e:
            logger.error("notify failed for chat_id=%s: %s", cid, e)
    print(f"Sent to {len(targets)} chat(s)")
    return 0


def _load_pool_accounts(pool: str) -> list[dict[str, Any]]:
    raw_gcs = load_json(accounts_json_path())
    raw_sh = load_shooter_doc()
    default_peers = parse_peer_ids(os.environ.get("TELEGRAM_OTP_PEER_IDS", "777000"), [777000])
    result: list[dict[str, Any]] = []
    if pool in ("gcs", "all"):
        result += load_otp_accounts(raw_gcs, project_root(), default_peers)
    if pool in ("shooter", "all"):
        # use load_shooter_login_accounts so `session` field is available
        result += load_shooter_login_accounts(raw_sh, project_root(), default_peers)
    return result


def _filter_pool_by_id(accounts: list[dict[str, Any]], target_id: str) -> list[dict[str, Any]]:
    if target_id.lower() == "all":
        return accounts
    key = target_id.strip().lower()

    def _str(v: Any) -> str:
        return str(v or "").strip().lower()

    # 1) prefix/contains match on id — returns ALL accounts whose id starts with or contains key
    #    e.g. "stmy" → STMY, STMY_LINA, STMY_ALICIA, STMY_RAISA, ...
    by_id = [a for a in accounts if key in _str(a.get("id"))]
    if by_id:
        return by_id

    # 2) prefix/contains match on label / name
    by_label = [
        a for a in accounts
        if key in _str(a.get("label")) or key in _str(a.get("name"))
    ]
    if by_label:
        return by_label

    # 3) match on phone number (exact or partial, strip spaces/dashes)
    clean_key = key.replace(" ", "").replace("-", "")
    by_phone = [
        a for a in accounts
        if clean_key in _str(a.get("phone")).replace(" ", "").replace("-", "")
    ]
    return by_phone


def _make_telethon_client(acc: dict[str, Any]) -> Any:
    from telethon.sync import TelegramClient as SyncClient
    session_path: Path = acc["session"]
    return SyncClient(
        str(session_path),
        acc["api_id"],
        acc["api_hash"],
        device_model="FRIDAY_BO",
    )


def _make_telethon_client_temp(acc: dict[str, Any]) -> tuple[Any, Path]:
    """
    Create Telethon client from a COPY of the session file (temp).
    Safe to run alongside `listen` — original file is not touched.
    Return (client, tmp_dir) — caller wajib hapus tmp_dir setelah selesai.
    """
    import shutil
    import tempfile
    from telethon.sync import TelegramClient as SyncClient

    session_path: Path = acc["session"]
    original = (
        Path(str(session_path) + ".session")
        if not str(session_path).endswith(".session")
        else session_path
    )
    tmp_dir = Path(tempfile.mkdtemp(prefix="otp_sess_"))
    tmp_file = tmp_dir / "session.session"
    shutil.copy2(original, tmp_file)
    tmp_base = tmp_dir / "session"   # Telethon akan tambah .session sendiri
    client = SyncClient(
        str(tmp_base),
        acc["api_id"],
        acc["api_hash"],
        device_model="FRIDAY_BO",
    )
    return client, tmp_dir


def _session_file_path(acc: dict[str, Any]) -> Path:
    session_path: Path = acc["session"]
    return (
        Path(str(session_path) + ".session")
        if not str(session_path).endswith(".session")
        else session_path
    )


def _session_file_ready(acc: dict[str, Any]) -> bool:
    sf = _session_file_path(acc)
    return sf.is_file() and sf.stat().st_size >= 1024


def _wait_session_file_ready(
    session_file: Path,
    *,
    min_bytes: int = 512,
    timeout_sec: float = 5.0,
) -> bool:
    """Wait for Telethon SQLite session to flush after login."""
    deadline = time.time() + max(0.5, timeout_sec)
    while time.time() < deadline:
        try:
            if session_file.is_file() and session_file.stat().st_size >= min_bytes:
                return True
        except OSError:
            pass
        time.sleep(0.25)
    try:
        return session_file.is_file() and session_file.stat().st_size >= min_bytes
    except OSError:
        return False


def _session_working(acc: dict[str, Any]) -> bool:
    """True if .session exists and Telethon is authorized (not expired)."""
    if not _session_file_ready(acc):
        return False
    client, tmp_dir = _make_telethon_client_temp(acc)
    try:
        client.connect()
        if not client.is_user_authorized():
            return False
        me = client.get_me()
        return bool(me)
    except Exception:
        return False
    finally:
        try:
            client.disconnect()
        except Exception:
            pass
        try:
            import shutil as _shutil

            _shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass


def run_list_sessions(pool: str, target_id: str, keep_device: str = "FRIDAY_BO") -> int:
    """List all active Telegram sessions for OTP accounts."""
    from telethon.tl.functions.account import GetAuthorizationsRequest

    logging.getLogger("telethon").setLevel(logging.WARNING)
    accounts = _load_pool_accounts(pool)
    accounts = _filter_pool_by_id(accounts, target_id)
    if not accounts:
        print(f"Account '{target_id}' not found in pool '{pool}'.", file=sys.stderr)
        return 2

    for acc in accounts:
        acc_id = str(acc.get("id") or "?")
        if not _session_file_ready(acc):
            print(f"\n[{acc_id}] ⏭ no session file, skip")
            continue

        profile = acc.get("profile_hint") or acc.get("label") or acc.get("name") or ""
        print(f"\n{'='*50}")
        print(f"Account : {acc_id}" + (f"  ({profile})" if profile else ""))
        print(f"Phone   : {acc.get('phone', '-')}")
        print(f"{'='*50}")

        client, tmp_dir = _make_telethon_client_temp(acc)
        try:
            client.connect()
            if not client.is_user_authorized():
                print("  ⏭ Not authorized, skip")
                continue

            result = client(GetAuthorizationsRequest())
            auths = result.authorizations

            for i, a in enumerate(auths, start=1):
                is_current = getattr(a, "current", False)
                device = getattr(a, "device_model", "?")
                platform = getattr(a, "platform", "?")
                app_name = getattr(a, "app_name", "?")
                app_version = getattr(a, "app_version", "?")
                ip = getattr(a, "ip", "?")
                country = getattr(a, "country", "?")
                region = getattr(a, "region", "?")
                date_active = getattr(a, "date_active", None)
                date_str = str(date_active)[:19] if date_active else "?"
                hash_val = getattr(a, "hash", 0)

                is_protected_device = keep_device and keep_device.lower() in device.lower()

                if is_current:
                    # This is the temp-copy query connection — auto-removed on disconnect
                    flag = "⚙ QUERY (temp — auto-removed after this command)"
                elif is_protected_device:
                    flag = f"🔒 PROTECTED — will NOT be terminated (keep-device: {keep_device})"
                else:
                    flag = "⚠ can be terminated"

                print(f"\n  [{i}] {flag}")
                print(f"      Device   : {device} / {platform}")
                print(f"      App      : {app_name} {app_version}")
                print(f"      IP       : {ip} ({country} {region})")
                print(f"      Last seen: {date_str}")
                print(f"      Hash     : {hash_val}")

        except Exception as e:
            print(f"  ✗ Error: {type(e).__name__}: {e}", file=sys.stderr)
        finally:
            try:
                client.disconnect()
            except Exception:
                pass
            try:
                import shutil as _shutil
                _shutil.rmtree(tmp_dir, ignore_errors=True)
            except Exception:
                pass
        time.sleep(0.3)

    return 0


def run_terminate_session(
    pool: str,
    target_id: str,
    session_ref: str,
    keep_device: str | None = "FRIDAY_BO",
) -> int:
    """
    Terminate a specific session on an OTP account.
    session_ref : index from list-sessions, hash value, or 'others'.
    keep_device : device name substring to always protect (default: FRIDAY_BO).
                  When session_ref='others', sessions whose device_model contains
                  keep_device are never terminated.
    """
    from telethon.tl.functions.account import GetAuthorizationsRequest, ResetAuthorizationRequest

    logging.getLogger("telethon").setLevel(logging.WARNING)
    accounts = _load_pool_accounts(pool)
    accounts = _filter_pool_by_id(accounts, target_id)
    if not accounts:
        print(f"Account '{target_id}' not found in pool '{pool}'.", file=sys.stderr)
        return 2
    if len(accounts) > 1:
        ids = ", ".join(str(a.get("id") or "?") for a in accounts)
        print(f"  ℹ {len(accounts)} accounts matched: {ids}")

    errors = 0
    for acc in accounts:
        acc_id = str(acc.get("id") or "?")
        if not _session_file_ready(acc):
            print(f"\n[{acc_id}] ⏭ no session file, skip")
            continue

        print(f"\n[{acc_id}] Connecting (temp copy — safe alongside listen)...", flush=True)
        client, tmp_dir = _make_telethon_client_temp(acc)
        try:
            client.connect()
            if not client.is_user_authorized():
                print(f"  ⏭ Not authorized, skip")
                continue

            result = client(GetAuthorizationsRequest())
            auths = result.authorizations
            current_hashes = {getattr(a, "hash", 0) for a in auths if getattr(a, "current", False)}

            def _is_protected(auth: Any) -> bool:
                """Return True if this session must never be terminated."""
                if getattr(auth, "current", False):
                    return True
                if keep_device:
                    device = getattr(auth, "device_model", "") or ""
                    if keep_device.lower() in device.lower():
                        return True
                return False

            protected = [a for a in auths if _is_protected(a)]
            others = [a for a in auths if not _is_protected(a)]

            to_terminate: list[Any] = []

            if session_ref.lower() == "others":
                to_terminate = others
                if protected:
                    kept_labels = ", ".join(
                        f"{getattr(a,'device_model','?')} / {getattr(a,'app_name','?')}"
                        for a in protected
                    )
                    print(f"  🔒 Protected (kept) : {kept_labels}")
            else:
                try:
                    idx = int(session_ref)
                    if 1 <= idx <= len(auths):
                        chosen = auths[idx - 1]
                        if _is_protected(chosen):
                            dev = getattr(chosen, "device_model", "?")
                            print(f"  ✗ Cannot terminate protected session: {dev} (matches keep-device or is current).")
                            errors += 1
                            continue
                        to_terminate = [chosen]
                    else:
                        print(f"  ✗ Index {idx} out of range (1–{len(auths)})")
                        errors += 1
                        continue
                except ValueError:
                    try:
                        hash_val = int(session_ref)
                        matched = [a for a in auths if getattr(a, "hash", None) == hash_val]
                        if not matched:
                            print(f"  ✗ No session with hash {hash_val}")
                            errors += 1
                            continue
                        if _is_protected(matched[0]):
                            dev = getattr(matched[0], "device_model", "?")
                            print(f"  ✗ Cannot terminate protected session: {dev}.")
                            errors += 1
                            continue
                        to_terminate = matched
                    except ValueError:
                        print(f"  ✗ Invalid session_ref '{session_ref}'. Use index number, hash, or 'others'.")
                        errors += 1
                        continue

            for auth in to_terminate:
                device = getattr(auth, "device_model", "?")
                app = getattr(auth, "app_name", "?")
                ip = getattr(auth, "ip", "?")
                country = getattr(auth, "country", "?")
                h = getattr(auth, "hash", 0)
                try:
                    client(ResetAuthorizationRequest(hash=h))
                    print(f"  ✓ Terminated: {device} / {app} | {ip} ({country})")
                except Exception as e:
                    print(f"  ✗ Failed to terminate {device}: {e}")
                    errors += 1

        except Exception as e:
            print(f"  ✗ {acc_id} error: {type(e).__name__}: {e}", file=sys.stderr)
            errors += 1
        finally:
            try:
                client.disconnect()
            except Exception:
                pass
            try:
                import shutil as _shutil
                _shutil.rmtree(tmp_dir, ignore_errors=True)
            except Exception:
                pass
        time.sleep(0.3)

    return 0 if errors == 0 else 1


def run_terminate_other_sessions(pool: str, target_id: str) -> int:
    """
    Terminate all Telegram sessions EXCEPT the current one for a specific account.
    pool  : 'gcs' | 'shooter' | 'all'
    target_id : account id (SH_VENAN_01 / STMY_CS01 / etc.) or 'all' to do every account
    """
    from telethon.tl.functions.account import GetAuthorizationsRequest, ResetAuthorizationRequest

    logging.getLogger("telethon").setLevel(logging.WARNING)

    raw_gcs = load_json(accounts_json_path())
    raw_sh = load_shooter_doc()
    default_peers = parse_peer_ids(os.environ.get("TELEGRAM_OTP_PEER_IDS", "777000"), [777000])

    pool_accounts: list[dict[str, Any]] = []
    if pool in ("gcs", "all"):
        pool_accounts += load_otp_accounts(raw_gcs, project_root(), default_peers)
    if pool in ("shooter", "all"):
        pool_accounts += load_shooter_accounts(raw_sh)

    if not pool_accounts:
        print("No accounts found.", file=sys.stderr)
        return 2

    if target_id.lower() != "all":
        key = target_id.strip().lower()
        pool_accounts = [a for a in pool_accounts if str(a.get("id") or "").strip().lower() == key]
        if not pool_accounts:
            print(f"Account '{target_id}' not found.", file=sys.stderr)
            return 2

    total_terminated = 0
    total_errors = 0

    for acc in pool_accounts:
        acc_id = str(acc.get("id") or "?")
        session_path: Path = acc["session"]
        session_file = (
            Path(str(session_path) + ".session")
            if not str(session_path).endswith(".session")
            else session_path
        )
        if not session_file.is_file() or session_file.stat().st_size < 1024:
            print(f"  ⏭ {acc_id} — no session file, skip")
            continue

        print(f"\n[{acc_id}] Connecting (temp copy — safe alongside listen)...", flush=True)
        client, tmp_dir = _make_telethon_client_temp(acc)
        try:
            client.connect()
            if not client.is_user_authorized():
                print(f"  ⏭ {acc_id} — not authorized, skip")
                continue

            result = client(GetAuthorizationsRequest())
            authorizations = result.authorizations
            current = [a for a in authorizations if getattr(a, "current", False)]
            others = [a for a in authorizations if not getattr(a, "current", False)]

            current_label = f"{current[0].device_model} / {current[0].app_name}" if current else "unknown"
            print(f"  Keep  : {current_label} ({len(current)} session)", flush=True)
            print(f"  Others: {len(others)} session(s) to terminate", flush=True)

            terminated = 0
            for auth in others:
                device = getattr(auth, "device_model", "?")
                app = getattr(auth, "app_name", "?")
                hash_val = getattr(auth, "hash", 0)
                try:
                    client(ResetAuthorizationRequest(hash=hash_val))
                    print(f"    ✓ Terminated: {device} / {app}")
                    terminated += 1
                except Exception as e:
                    print(f"    ✗ Failed to terminate {device} / {app}: {e}")
                    total_errors += 1

            total_terminated += terminated
            print(f"  Done: {terminated} terminated for {acc_id}")

        except Exception as e:
            print(f"  ✗ {acc_id} error: {type(e).__name__}: {e}", file=sys.stderr)
            total_errors += 1
        finally:
            try:
                client.disconnect()
            except Exception:
                pass
            try:
                import shutil as _shutil
                _shutil.rmtree(tmp_dir, ignore_errors=True)
            except Exception:
                pass
        time.sleep(0.3)

    print(f"\n{'='*40}")
    print(f"Total terminated : {total_terminated}")
    print(f"Total errors     : {total_errors}")
    print(f"{'='*40}")
    return 0 if total_errors == 0 else 1


_login_fail_cooldown_until: dict[str, float] = {}
_login_awaiting_otp: dict[str, float] = {}
_login_wait_otp_logged_at: dict[str, float] = {}
_listen_pending_logged: set[str] = set()
_listen_failed_cooldown_until: dict[str, float] = {}
_listen_watch_tasks: dict[str, asyncio.Task[None]] = {}


def _login_sheet_code_enabled() -> bool:
    if not os.environ.get("GOOGLE_SHEET_ID", "").strip():
        return False
    return os.environ.get("TELEGRAM_LOGIN_SHEET_CODE", "1").strip().lower() not in (
        "0",
        "false",
        "no",
        "off",
    )


def _sheet_clear_code_after_login() -> bool:
    return os.environ.get("TELEGRAM_SHEET_CLEAR_CODE_AFTER_LOGIN", "1").strip().lower() not in (
        "0",
        "false",
        "no",
        "off",
    )


def _make_login_code_callback(
    root: Path,
    account_id: str,
    phone: str,
    *,
    max_otp_retries: int,
    preset_code: str = "",
    quiet: bool = False,
    on_wrong_code: Callable[[int, int], None] | None = None,
) -> Callable[[], str]:
    """Wait for OTP column (L) in Google Sheet; optional terminal fallback."""
    otp_attempt = [0]
    use_sheet = _login_sheet_code_enabled() and not preset_code
    wait_sec = _env_int("TELEGRAM_SHEET_LOGIN_WAIT_SEC", 180, minimum=30)
    poll_sec = max(1.0, float(os.environ.get("TELEGRAM_SHEET_LOGIN_POLL_SEC", "2").strip() or "2"))
    fallback_tty = os.environ.get("TELEGRAM_LOGIN_SHEET_FALLBACK_TTY", "0").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )

    def _cb() -> str:
        otp_attempt[0] += 1
        if otp_attempt[0] > 1:
            print(
                f"  ⚠ Wrong code, retry {otp_attempt[0]}/{max_otp_retries} "
                f"(update OTP column in Sheet)...",
                flush=True,
            )
            if on_wrong_code:
                on_wrong_code(otp_attempt[0], max_otp_retries)
        if otp_attempt[0] > max_otp_retries:
            raise RuntimeError(f"OTP failed after {max_otp_retries} attempts")

        if preset_code:
            return preset_code

        if use_sheet:
            import sheets_sync

            np = sheets_sync.norm_phone(phone)
            if not quiet:
                print(
                    f"  Waiting for OTP in Sheet ({account_id} | {phone}) "
                    f"up to {wait_sec}s...",
                    flush=True,
                )
            deadline = time.time() + wait_sec
            while time.time() < deadline:
                codes = sheets_sync.fetch_login_codes_by_phone(root, force=True)
                code = codes.get(np, "") if np else ""
                if code:
                    if not quiet:
                        print(f"  ✓ Sheet OTP received for {account_id}", flush=True)
                    if _sheet_clear_code_after_login() and np:
                        sheets_sync.clear_login_code_in_sheet(root, np)
                    return code
                time.sleep(poll_sec)
            if fallback_tty:
                return input(f"[OTP {account_id} | {phone}] Enter code: ")
            raise RuntimeError(
                f"Sheet OTP timeout ({wait_sec}s) — fill OTP column in Google Sheet"
            )

        return input(f"[OTP {account_id} | {phone}] Enter code: ")

    return _cb


def _apply_sheet_login_fields(acc: dict[str, Any], root: Path) -> str:
    """Merge 2FA/password from Google Sheet into account dict (by phone)."""
    import sheets_sync

    phone = sheets_sync.norm_phone(str(acc.get("phone") or ""))
    if phone:
        passwords = sheets_sync.fetch_passwords_by_phone(root)
        pw = (passwords.get(phone) or "").strip()
        if pw:
            acc["password"] = pw
    return str(acc.get("password") or "").strip()


def _make_login_password_callback(
    root: Path,
    account_id: str,
    phone: str,
    *,
    preset_password: str = "",
) -> Callable[[], str]:
    """Wait for 2FA column in Google Sheet; optional terminal fallback."""
    use_sheet = _login_sheet_code_enabled()
    wait_sec = _env_int("TELEGRAM_SHEET_LOGIN_WAIT_SEC", 180, minimum=30)
    poll_sec = max(1.0, float(os.environ.get("TELEGRAM_SHEET_LOGIN_POLL_SEC", "2").strip() or "2"))
    fallback_tty = os.environ.get("TELEGRAM_LOGIN_SHEET_FALLBACK_TTY", "0").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )

    def _cb() -> str:
        import sheets_sync

        np = sheets_sync.norm_phone(phone)
        if use_sheet and np:
            passwords = sheets_sync.fetch_passwords_by_phone(root, force=True)
            pw = (passwords.get(np) or preset_password or "").strip()
            if pw:
                print(f"  ✓ Sheet 2FA received for {account_id}", flush=True)
                return pw
            print(
                f"  Waiting for 2FA in Sheet ({account_id} | {phone}) "
                f"up to {wait_sec}s...",
                flush=True,
            )
            deadline = time.time() + wait_sec
            while time.time() < deadline:
                passwords = sheets_sync.fetch_passwords_by_phone(root, force=True)
                pw = (passwords.get(np) or "").strip()
                if pw:
                    print(f"  ✓ Sheet 2FA received for {account_id}", flush=True)
                    return pw
                time.sleep(poll_sec)
            if fallback_tty:
                import getpass

                return getpass.getpass(f"[2FA {account_id} | {phone}] Password: ")
            raise RuntimeError(
                f"Sheet 2FA timeout ({wait_sec}s) — fill 2FA column in Google Sheet"
            )

        if preset_password:
            return preset_password
        import getpass

        return getpass.getpass(f"[2FA {account_id} | {phone}] Password: ")

    return _cb


def _login_single_account(
    acc: dict[str, Any],
    json_list_key: str,
    label: str,
    *,
    preset_code: str = "",
    quiet: bool = False,
    live_notify: bool = False,
) -> tuple[bool, str]:
    """Telethon login for one account; code from Sheet (poll) or preset_code."""
    root = project_root()
    logging.getLogger("telethon").setLevel(logging.WARNING)
    json_path = _json_path_for_list_key(json_list_key)
    json_label = "shooteraccounts.json" if json_list_key == "shooter_accounts" else "accounts.json"

    acc_id = str(acc.get("id") or "?")
    acc_phone = str(acc.get("phone") or "-")
    session_path: Path = acc["session"]
    session_path.parent.mkdir(parents=True, exist_ok=True)
    session_file = _session_file_path(acc)
    if _session_working(acc):
        if not quiet:
            print(f"  ✓ {acc_id} — session already authorized", flush=True)
        return True, ""
    if session_file.is_file():
        _safe_unlink_session_file(session_file)
        if not quiet:
            print(f"  ↻ {acc_id} — expired/invalid session removed, re-login", flush=True)

    if not quiet:
        print(f"\n[{label}] {acc_id} ({acc_phone})", flush=True)

    kw: dict[str, Any] = {}
    if acc.get("phone"):
        kw["phone"] = acc["phone"]

    sheet_pw = _apply_sheet_login_fields(acc, root)
    if _login_sheet_code_enabled():
        kw["password"] = _make_login_password_callback(
            root,
            acc_id,
            acc_phone,
            preset_password=sheet_pw,
        )
    elif sheet_pw:
        kw["password"] = sheet_pw

    max_otp_retries = _env_int("TELEGRAM_LOGIN_OTP_RETRIES", 3, minimum=1)

    def _on_wrong_code(attempt: int, max_r: int) -> None:
        if live_notify:
            notify_live_login_event(
                acc,
                "wrong_otp",
                label=label,
                detail=f"Retry {attempt}/{max_r} — update OTP column in Sheet",
            )

    kw["code_callback"] = _make_login_code_callback(
        root,
        acc_id,
        acc_phone,
        max_otp_retries=max_otp_retries,
        preset_code=preset_code.strip(),
        quiet=quiet,
        on_wrong_code=_on_wrong_code if live_notify else None,
    )

    conn_retries = _env_int("TELETHON_CONNECTION_RETRIES", 5, minimum=1)
    req_retries = _env_int("TELETHON_REQUEST_RETRIES", 5, minimum=1)
    sqlite_retries = _env_int("TELEGRAM_LOGIN_SQLITE_RETRIES", 12, minimum=1)

    client: TelegramClient | None = None
    login_ok = False
    for attempt in range(sqlite_retries):
        if client is not None:
            try:
                client.disconnect()
            except Exception:
                pass
            time.sleep(0.4 * (attempt + 1))
        if not quiet:
            print("  Connecting to Telegram (SMS may be sent)...", flush=True)
        client = TelegramClient(
            str(session_path),
            acc["api_id"],
            acc["api_hash"],
            device_model="FRIDAY_BO",
            connection_retries=conn_retries,
            request_retries=req_retries,
        )
        try:
            client.start(**kw) if kw else client.start()
            login_ok = True
            break
        except sqlite3.OperationalError as e:
            if "locked" not in str(e).lower():
                try:
                    client.disconnect()
                except Exception:
                    pass
                raise
            try:
                client.disconnect()
            except Exception:
                pass
            client = None
            if attempt + 1 >= sqlite_retries:
                print(
                    f"ERROR: SQLite session locked for {acc_id} — stop LISTEN for this account.",
                    file=sys.stderr,
                )
                return False, "SQLite session locked"
            time.sleep(min(3.0, 0.6 * (attempt + 1)))
        except RuntimeError as e:
            if not quiet:
                print(f"SKIP: {acc_id} — {e}", file=sys.stderr)
            try:
                if client:
                    client.disconnect()
            except Exception:
                pass
            if session_file.is_file():
                session_file.unlink(missing_ok=True)
            break
        except Exception as e:
            if not quiet:
                print(f"  ✗ {acc_id} login failed — {type(e).__name__}: {e}", file=sys.stderr)
            try:
                if client:
                    client.disconnect()
            except Exception:
                pass
            if session_file.is_file():
                session_file.unlink(missing_ok=True)
            break

    ok = False
    fail_reason = ""
    profile_name = acc_id
    if login_ok and client:
        me = None
        try:
            if client.is_connected():
                if not client.loop.run_until_complete(client.is_user_authorized()):
                    fail_reason = "not authorized after start()"
                else:
                    me = client.loop.run_until_complete(client.get_me())
                    if not me:
                        fail_reason = "get_me() returned empty"
        except Exception as e:
            fail_reason = f"verify after login: {e!s}"
        try:
            if client.is_connected():
                client.loop.run_until_complete(client.disconnect())
        except Exception:
            pass
        time.sleep(0.4)
        if me:
            profile_name = profile_name_from_me(me, acc_id)
            if not quiet:
                print(f"  ✓ Verified: {profile_name}")
            update_json_profile_hint(json_path, json_list_key, acc_id, profile_name)
        session_ok = _wait_session_file_ready(session_file)
        if me and session_ok:
            if not quiet:
                print(f"  ✓ Session saved: {session_file.name} ({session_file.stat().st_size} bytes)")
            ok = True
        elif me and not session_ok:
            time.sleep(1.0)
            session_ok = _wait_session_file_ready(session_file, timeout_sec=4.0)
            if session_ok:
                if not quiet:
                    print(f"  ✓ Session saved (delayed flush): {session_file.name}")
                ok = True
            elif _session_working(acc):
                if not quiet:
                    print(f"  ✓ Session authorized (file check skipped)", flush=True)
                ok = True
            else:
                fail_reason = fail_reason or "session file not ready after login"
        elif not me and _session_working(acc):
            if not quiet:
                print(f"  ✓ Session authorized (recovered after verify glitch)", flush=True)
            ok = True
        elif not fail_reason:
            fail_reason = "login verification failed"
        if ok:
            pool_name = "shooter" if json_list_key == "shooter_accounts" else "gcs"
            _after_login_sync_status(acc, pool_name)
            _run_sync_push_delta(project_root(), verbose=False)
    elif not fail_reason:
        fail_reason = "Telegram login did not complete"
    return ok, fail_reason


def _collect_accounts_needing_session(root: Path) -> list[tuple[str, dict[str, Any], str]]:
    """(json_list_key, account, pool_name) for accounts without .session."""
    default_peers = parse_peer_ids(os.environ.get("TELEGRAM_OTP_PEER_IDS", "777000"), [777000])
    out: list[tuple[str, dict[str, Any], str]] = []
    raw_gcs = load_json(accounts_json_path())
    for acc in load_otp_accounts(raw_gcs, root, default_peers):
        if not _session_file_ready(acc):
            out.append(("otp_accounts", acc, "gcs"))
    raw_sh = load_shooter_doc()
    for acc in load_shooter_login_accounts(raw_sh, root, default_peers):
        if not _session_file_ready(acc):
            out.append(("shooter_accounts", acc, "shooter"))
    return out


def _pending_trigger_phones_from_sheet(root: Path) -> set[str]:
    """Phone numbers with column I (Status) = login trigger (default Pending)."""
    import sheets_sync

    return sheets_sync.fetch_phones_by_sheet_status(root)


def _phones_registered_in_json(root: Path, phones: set[str]) -> set[str]:
    """Subset of `phones` that exist in accounts.json or shooteraccounts.json."""
    import sheets_sync

    if not phones:
        return set()
    found: set[str] = set()
    default_peers = parse_peer_ids(os.environ.get("TELEGRAM_OTP_PEER_IDS", "777000"), [777000])
    raw_gcs = load_json(accounts_json_path())
    for acc in load_otp_accounts(raw_gcs, root, default_peers):
        p = sheets_sync.norm_phone(str(acc.get("phone") or ""))
        if p in phones:
            found.add(p)
    raw_sh = load_shooter_doc()
    for acc in load_shooter_login_accounts(raw_sh, root, default_peers):
        p = sheets_sync.norm_phone(str(acc.get("phone") or ""))
        if p in phones:
            found.add(p)
    return found


def _account_sheet_login_pending(root: Path, acc: dict[str, Any]) -> bool:
    """True while Sheet Status = Pending — LISTEN must wait for LIVE-LOGIN."""
    if not os.environ.get("GOOGLE_SHEET_ID", "").strip():
        return False
    try:
        import sheets_sync

        phone = sheets_sync.norm_phone(str(acc.get("phone") or ""))
        if not phone:
            return False
        return phone in sheets_sync.fetch_phones_by_sheet_status(root)
    except Exception:
        return False


def _collect_accounts_pending_login(root: Path) -> list[tuple[str, dict[str, Any], str]]:
    """
    Accounts where Sheet column I (Status) = Pending (login trigger).
    Includes rows that already have .session (finalize Sheet without re-login).
    Call _run_sync_pull first so new Sheet rows are registered in JSON.
    """
    import sheets_sync

    trigger_phones = sheets_sync.fetch_phones_by_sheet_status(root)
    if not trigger_phones:
        return []

    default_peers = parse_peer_ids(os.environ.get("TELEGRAM_OTP_PEER_IDS", "777000"), [777000])
    out: list[tuple[str, dict[str, Any], str]] = []
    seen: set[str] = set()

    def _add(json_key: str, acc: dict[str, Any], pool: str) -> None:
        phone = sheets_sync.norm_phone(str(acc.get("phone") or ""))
        if not phone or phone not in trigger_phones or phone in seen:
            return
        seen.add(phone)
        out.append((json_key, acc, pool))

    raw_gcs = load_json(accounts_json_path())
    for acc in load_otp_accounts(raw_gcs, root, default_peers):
        _add("otp_accounts", acc, "gcs")
    raw_sh = load_shooter_doc()
    for acc in load_shooter_login_accounts(raw_sh, root, default_peers):
        _add("shooter_accounts", acc, "shooter")
    return out


def _run_login_all(accounts: list[dict[str, Any]], json_list_key: str, label: str) -> int:
    if not accounts:
        print(f"No valid {label} accounts found.", file=sys.stderr)
        return 2

    need_login: list[dict[str, Any]] = []
    already_ok: list[str] = []
    for acc in accounts:
        if _session_file_ready(acc):
            already_ok.append(str(acc.get("id") or ""))
        else:
            need_login.append(acc)

    print(f"[{label}] Total: {len(accounts)} | Already logged in: {len(already_ok)} | Need login: {len(need_login)}")
    if already_ok:
        print(f"  Skip: {len(already_ok)} account(s) (session already exists)")
    json_label = "shooteraccounts.json" if json_list_key == "shooter_accounts" else "accounts.json"
    if already_ok:
        ok_rows = [a for a in accounts if str(a.get("id")) in set(already_ok)]
        print(f"\n--- Sync profile ({len(ok_rows)} logged in) → {json_label} ---", flush=True)
        n = sync_profiles_to_json(ok_rows, json_list_key)
        print(f"  Done: {n} profile(s)\n", flush=True)

    if not need_login:
        print(f"\nAll {label} accounts already have a session.")
        return 0
    if _login_sheet_code_enabled():
        print(
            "\nOTP: fill OTP column in Google Sheet when SMS arrives "
            "(no terminal typing needed).",
            flush=True,
        )
    else:
        print("\nTip: stop `listen` first to avoid database locked errors.", flush=True)

    results_ok: list[str] = []
    results_fail: list[str] = []
    for idx, acc in enumerate(need_login, start=1):
        acc_id = str(acc.get("id") or f"acc{idx}")
        print(f"\n[{idx}/{len(need_login)}]", end=" ", flush=True)
        ok, _fail = _login_single_account(acc, json_list_key, label)
        if ok:
            results_ok.append(acc_id)
        else:
            results_fail.append(acc_id)
        time.sleep(0.25)

    print("\n" + "=" * 40)
    print(f"  LOGIN-ALL SUMMARY ({label})")
    print("=" * 40)
    print(f"  Already OK : {len(already_ok)}")
    print(f"  New Login  : {len(results_ok)}")
    if results_ok:
        for r in results_ok:
            print(f"    ✓ {r}")
    if results_fail:
        print(f"  Failed     : {len(results_fail)}")
        for r in results_fail:
            print(f"    ✗ {r}")
    print(f"  Total      : {len(accounts)}")
    print("=" * 40 + "\n")

    return 0


def run_login_all() -> int:
    root = project_root()
    raw = load_json(accounts_json_path())
    default_peers = parse_peer_ids(os.environ.get("TELEGRAM_OTP_PEER_IDS", "777000"), [777000])
    accounts = load_otp_accounts(raw, root, default_peers)
    return _run_login_all(accounts, "otp_accounts", "GCS")


def run_login_all_shooter() -> int:
    root = project_root()
    raw = load_shooter_doc()
    accounts = load_shooter_login_accounts(raw, root)
    if not accounts:
        print(
            "No valid shooter_accounts (need id, owner, phone, api_id, api_hash).",
            file=sys.stderr,
        )
        return 2
    return _run_login_all(accounts, "shooter_accounts", "Shooter")


async def _listen_start_account(
    acc: dict[str, Any],
    *,
    tag: str,
    accounts_doc: dict[str, Any],
    brands_cfg: dict[str, dict[str, Any]],
    token: str,
    loose: bool,
    template: str,
    require_req: bool,
    send_copy_line: bool,
    copy_line_template: str,
    sync_profile_on_listen: bool,
    conn_retries: int,
    req_retries: int,
    clients: list[tuple[TelegramClient, dict[str, Any]]],
    active: list[str],
    expired: list[str],
    skipped: list[str],
    profile_synced: list[str],
    quiet: bool = False,
) -> None:
    pool = account_pool(acc)
    list_key = "shooter_accounts" if pool == "shooter" else "otp_accounts"
    json_path = _json_path_for_list_key(list_key)
    acc_id = str(acc.get("id", "?"))

    session_path: Path = acc["session"]
    session_path.parent.mkdir(parents=True, exist_ok=True)
    session_file = (
        Path(str(session_path) + ".session")
        if not str(session_path).endswith(".session")
        else session_path
    )
    if not session_file.is_file() or session_file.stat().st_size < 1024:
        skipped.append(listener_account_display_name(acc, acc_id))
        if _account_sheet_login_pending(project_root(), acc):
            if not quiet and acc_id not in _listen_pending_logged:
                print(f"  [{tag}] ⏭ {acc_id} — Pending (waiting LIVE-LOGIN + OTP in Sheet)", flush=True)
                _listen_pending_logged.add(acc_id)
            _listen_mark_login_wait(acc_id)
        return

    root = project_root()
    if _account_sheet_login_pending(root, acc):
        if not quiet and acc_id not in _listen_pending_logged:
            print(f"  [{tag}] ⏭ {acc_id} — Pending (waiting LIVE-LOGIN + OTP in Sheet)", flush=True)
            _listen_pending_logged.add(acc_id)
        _listen_mark_login_wait(acc_id)
        return

    client = TelegramClient(
        str(session_path),
        acc["api_id"],
        acc["api_hash"],
        device_model="FRIDAY_BO",
        connection_retries=conn_retries,
        request_retries=req_retries,
    )

    @client.on(events.NewMessage(incoming=True, from_users=acc["peer_ids"]))
    async def handler(event, _acc=acc, _tag=tag) -> None:
        msg_text = getattr(event.message, "raw_text", None) or (event.message.message or "") or ""
        code = extract_login_code(msg_text, loose)
        if not code:
            return
        if is_recent_otp_duplicate(str(_acc["id"]), code):
            logger.info("[%s] %s duplicate OTP, skipped.", _tag, _acc["id"])
            return
        req = get_active_login_request(str(_acc["id"]))
        if require_req and not req:
            req_cur = account_currency_for_request(_acc, brands_cfg)
            logger.info(
                "[%s] %s OTP received without login request — send /login %s in the %s topic first.",
                _tag,
                _acc["id"],
                _acc["id"],
                req_cur,
            )
            if _manual_login_alert_enabled():
                acc_id_str = str(_acc["id"])
                baseline_hashes: set[int] = set()
                try:
                    existing = await _collect_non_friday_authorizations(client)
                    baseline_hashes = {int(x.get("hash") or 0) for x in existing if x.get("hash")}
                except Exception as e:
                    logger.debug("[%s] %s manual login auth scan: %s", _tag, acc_id_str, e)
                asyncio.create_task(
                    _manual_login_success_scan(
                        client,
                        _acc,
                        accounts_doc,
                        baseline_hashes,
                    )
                )
            return
        send_targets = build_otp_send_targets(accounts_doc, _acc, brands_cfg, req)
        if not send_targets:
            logger.error("[%s] %s no OTP send target found.", _tag, _acc["id"])
            return
        profile = str(_acc.get("detected_profile") or _acc.get("profile_hint") or _acc["id"])
        pw_raw = _acc.get("password")
        pw_str = str(pw_raw).strip() if pw_raw else ""
        if os.environ.get("TELEGRAM_OTP_MASK_2FA", "0").strip().lower() in ("1", "true", "yes", "on"):
            password_display = "••••••••" if pw_str else "—"
        else:
            password_display = html.escape(pw_str) if pw_str else "—"
        msg = format_otp_alert_message(code, password_display, template or None)
        otp_markup = build_otp_inline_keyboard(code, pw_str or None)
        ok_chats: list[str] = []
        send_errors: list[str] = []
        for cid, tid in send_targets:
            try:
                await asyncio.to_thread(send_message, token, cid, msg, "HTML", tid, otp_markup)
                if send_copy_line:
                    copy_line = copy_line_template.replace("{code}", code)
                    await asyncio.to_thread(send_message, token, cid, copy_line, None, tid)
                label = f"{cid}:{tid}" if tid else str(cid)
                ok_chats.append(label)
            except Exception as e:
                send_errors.append(f"{cid}: {e!s}")
                logger.error("[%s] %s send failed: %s", _tag, _acc["id"], e)
        if ok_chats:
            logger.info("[%s] %s OTP diteruskan.", _tag, _acc["id"])
            record_otp_sent(str(_acc["id"]), code)
            if req:
                clear_login_request(str(_acc["id"]))

    kw: dict[str, Any] = {}
    if acc.get("phone"):
        kw["phone"] = acc["phone"]
    if acc.get("password"):
        kw["password"] = acc["password"]

    def _no_interactive_code(_aid: str = acc_id):
        raise RuntimeError(f"[{_aid}] Session expired — fill OTP column in Sheet (LIVE-LOGIN).")

    kw["code_callback"] = lambda: _no_interactive_code()

    if not quiet:
        print(f"  [{tag}] Connecting {acc_id}...", flush=True)
    try:
        await client.start(**kw) if kw else await client.start()
    except Exception as e:
        err_text = str(e).lower()
        if _account_sheet_login_pending(root, acc) or "fill otp column in sheet" in err_text:
            skipped.append(listener_account_display_name(acc, acc_id))
            if not quiet:
                print(f"  [{tag}] ⏭ {acc_id} — waiting for LIVE-LOGIN", flush=True)
            _listen_mark_login_wait(acc_id)
            try:
                await client.disconnect()
            except Exception:
                pass
            return
        if "database is locked" in err_text:
            if not quiet:
                print(f"  [{tag}] ✗ {acc_id} — database locked (retry later)", flush=True)
            else:
                logger.info("[%s] %s database locked (hot-reload retry later)", tag, acc_id)
            try:
                await client.disconnect()
            except Exception:
                pass
            return
        user_st = _classify_account_sheet_status(e)
        profile_hint = str(acc.get("profile_hint") or acc_id)
        if user_st == "Frozen":
            user_st = "Disconnected"
        expired.append(listener_account_display_name(acc, acc_id, profile_hint))
        if not quiet:
            print(f"  [{tag}] ✗ {acc_id} — {user_st}", flush=True)
        else:
            logger.info("[%s] %s hot-reload failed: %s", tag, acc_id, user_st)
        _publish_account_status(
            acc,
            pool,
            user_st,
            token=token,
            accounts_doc=accounts_doc,
            profile=profile_hint,
            note=str(e)[:120],
            notify=False,
            from_listen=True,
        )
        try:
            await client.disconnect()
        except Exception:
            pass
        # For SQLite lock, do not force-delete session to avoid cascading errors.
        if "database is locked" not in err_text:
            _safe_unlink_session_file(session_file)
        return

    verified = False
    me = None
    for _attempt in range(2):
        try:
            me = await client.get_me()
            if me:
                verified = True
                break
        except Exception:
            if _attempt == 0:
                try:
                    await client.disconnect()
                except Exception:
                    pass
                await asyncio.sleep(1)
                try:
                    await client.connect()
                except Exception:
                    break

    if not verified:
        profile_hint = str(acc.get("profile_hint") or acc_id)
        expired.append(listener_account_display_name(acc, acc_id, profile_hint))
        if not quiet:
            print(f"  [{tag}] ✗ {acc_id} — get_me() failed", flush=True)
        else:
            logger.info("[%s] %s hot-reload get_me() failed", tag, acc_id)
        _publish_account_status(
            acc,
            pool,
            "Expired",
            token=token,
            accounts_doc=accounts_doc,
            profile=profile_hint,
            note="get_me failed",
            notify=False,
            from_listen=True,
        )
        try:
            await client.disconnect()
        except Exception:
            pass
        _safe_unlink_session_file(session_file)
        return

    profile_name = profile_name_from_me(me, acc_id)
    user_st = account_status_from_me(me)

    if user_st == "Frozen":
        # Confirmed via get_me().restricted=True only — purge JSON + disconnect listener.
        expired.append(listener_account_display_name(acc, acc_id, profile_name))
        _publish_account_status(
            acc,
            pool,
            user_st,
            token=token,
            accounts_doc=accounts_doc,
            profile=profile_name,
            notify=False,
            frozen_confirmed=True,
            from_listen=True,
        )
        if not quiet:
            print(
                f"  [{tag}] 🗑 {acc_id} — Frozen (removed from JSON · re-login via Sheet Pending)",
                flush=True,
            )
        else:
            logger.info("[%s] %s frozen — removed from JSON", tag, acc_id)
        try:
            await client.disconnect()
        except Exception:
            pass
        return
    elif user_st in ("Banned", "Expired"):
        expired.append(listener_account_display_name(acc, acc_id, profile_name))
        if not quiet:
            print(f"  [{tag}] ✗ {acc_id} — {user_st}", flush=True)
        else:
            logger.info("[%s] %s hot-reload status: %s", tag, acc_id, user_st)
        _publish_account_status(
            acc,
            pool,
            user_st,
            token=token,
            accounts_doc=accounts_doc,
            profile=profile_name,
            notify=user_st == "Banned",
            from_listen=True,
        )
        try:
            await client.disconnect()
        except Exception:
            pass
        if user_st == "Expired":
            _safe_unlink_session_file(session_file)
        return

    prev_st = _known_account_status(acc)
    if prev_st.lower() in ("frozen", "expired", "disconnected"):
        try:
            import sheets_sync

            sheet_st = sheets_sync.sheet_status_after_login_value()
        except Exception:
            sheet_st = "Ready"
        _mark_account_status_known(acc, "Active")
        _queue_sheet_status(
            acc_id,
            pool,
            sheet_st.lower(),
            f"recovered from {prev_st}",
            phone=str(acc.get("phone") or ""),
            session_user=sheet_st,
            session_friday="Active",
            allow_instant=False,
            force_queue=True,
        )
        if not quiet:
            print(f"  [{tag}] ↺ {acc_id} — recovered ({prev_st} → {sheet_st}/Active)", flush=True)

    acc["detected_profile"] = profile_name
    if sync_profile_on_listen:
        old_hint = str(acc.get("profile_hint") or "").strip()
        if update_json_profile_hint(json_path, list_key, acc_id, profile_name):
            acc["profile_hint"] = profile_name
            if profile_name != old_hint:
                profile_synced.append(acc_id)
        if me:
            _register_listen_profile_handlers(
                client,
                acc,
                me_id=me.id,
                list_key=list_key,
                json_path=json_path,
                tag=tag,
            )
    active.append(f"{acc_id} ({profile_name})")
    if not quiet:
        print(f"  [{tag}] ✓ {acc_id} → {profile_name}", flush=True)
    clients.append((client, acc))


def _listen_hot_reload_enabled() -> bool:
    return os.environ.get("TELEGRAM_LISTEN_HOT_RELOAD", "1").strip().lower() not in (
        "0",
        "false",
        "no",
        "off",
    )


def _listen_failed_retry_sec() -> int:
    return _env_int("TELEGRAM_LISTEN_FAILED_RETRY_SEC", 300, minimum=60)


def _listen_hot_reload_interval_sec() -> int:
    return _env_int("TELEGRAM_LISTEN_RELOAD_INTERVAL_SEC", 45, minimum=15)


def _listen_mark_login_wait(acc_id: str) -> None:
    aid = str(acc_id or "").strip()
    if aid:
        _listen_failed_cooldown_until[aid] = time.time() + _listen_failed_retry_sec()


def _listen_failed_cooldown_active(acc_id: str) -> bool:
    aid = str(acc_id or "").strip()
    if not aid:
        return False
    until = _listen_failed_cooldown_until.get(aid, 0.0)
    return until > time.time()


def _listen_spawn_watch(
    listen_kw: dict[str, Any],
    cl: TelegramClient,
    acc_info: dict[str, Any],
) -> None:
    acc_id = str(acc_info.get("id") or "")
    old = _listen_watch_tasks.pop(acc_id, None)
    if old is not None and not old.done():
        old.cancel()
    _listen_watch_tasks[acc_id] = asyncio.create_task(_watch_client_loop(cl, acc_info, listen_kw))


async def _listen_stop_watch(listen_kw: dict[str, Any], acc_id: str) -> None:
    task = _listen_watch_tasks.pop(str(acc_id or ""), None)
    if task is not None and not task.done():
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


async def _listen_disconnect_client(
    listen_kw: dict[str, Any],
    cl: TelegramClient,
    acc_id: str,
) -> None:
    await _listen_stop_watch(listen_kw, acc_id)
    try:
        await cl.disconnect()
    except Exception:
        pass


def _listen_load_candidates(
    *,
    root: Path,
    default_peers: list[int],
    listen_shooter: bool,
    listen_kw: dict[str, Any],
) -> tuple[list[tuple[str, dict[str, Any]]], set[str]]:
    accounts_doc = load_json(accounts_json_path())
    brands_cfg = load_brands_config(accounts_doc)
    listen_kw["accounts_doc"] = accounts_doc
    listen_kw["brands_cfg"] = brands_cfg
    gcs_accounts = load_otp_accounts(accounts_doc, root, default_peers)
    shooter_accounts: list[dict[str, Any]] = []
    if listen_shooter:
        shooter_doc = load_shooter_doc()
        shooter_accounts = load_shooter_login_accounts(shooter_doc, root, default_peers)
    candidates: list[tuple[str, dict[str, Any]]] = [
        ("GCS", acc) for acc in gcs_accounts
    ] + [("SHOOTER", acc) for acc in shooter_accounts]
    json_ids = {str(acc.get("id") or "") for _, acc in candidates if str(acc.get("id") or "")}
    return candidates, json_ids


async def _listen_sync_accounts(
    *,
    root: Path,
    default_peers: list[int],
    listen_shooter: bool,
    listen_kw: dict[str, Any],
) -> None:
    """Sync LISTEN with JSON — add new accounts, remove deleted ones (incremental only)."""
    removed_count = 0
    clients: list[tuple[TelegramClient, dict[str, Any]]] = listen_kw["clients"]

    try:
        candidates, json_ids = _listen_load_candidates(
            root=root,
            default_peers=default_peers,
            listen_shooter=listen_shooter,
            listen_kw=listen_kw,
        )
    except Exception as e:
        print(f"  [Hot-reload] sync failed to read JSON: {e}", flush=True)
        return

    active_ids = {str(acc.get("id") or "") for _, acc in clients}
    for idx in range(len(clients) - 1, -1, -1):
        cl, acc_info = clients[idx]
        acc_id = str(acc_info.get("id") or "")
        if not acc_id or acc_id in json_ids:
            continue
        await _listen_disconnect_client(listen_kw, cl, acc_id)
        clients.pop(idx)
        active_ids.discard(acc_id)
        _listen_pending_logged.discard(acc_id)
        _listen_failed_cooldown_until.pop(acc_id, None)
        removed_count += 1

    new_started = 0
    for tag, acc in candidates:
        acc_id = str(acc.get("id") or "")
        if not acc_id or acc_id in active_ids:
            continue
        if _account_sheet_login_pending(root, acc):
            continue
        if not _session_file_ready(acc):
            continue
        if _listen_failed_cooldown_active(acc_id):
            continue
        n_before = len(clients)
        hr_skipped: list[str] = []
        hr_expired: list[str] = []
        hr_active: list[str] = []
        hr_sync: list[str] = []
        await _listen_start_account(
            acc,
            tag=tag,
            skipped=hr_skipped,
            expired=hr_expired,
            active=hr_active,
            profile_synced=hr_sync,
            quiet=True,
            **listen_kw,
        )
        if len(clients) > n_before:
            cl, acc_info = clients[-1]
            _listen_spawn_watch(listen_kw, cl, acc_info)
            active_ids.add(acc_id)
            _listen_failed_cooldown_until.pop(acc_id, None)
            new_started += 1

    if new_started or removed_count:
        parts: list[str] = []
        if new_started:
            parts.append(f"+{new_started} new")
        if removed_count:
            parts.append(f"-{removed_count} removed")
        print(
            f"  [Hot-reload] {', '.join(parts)} (total {len(clients)} listener(s))",
            flush=True,
        )


async def _listen_hot_reload_loop(
    *,
    root: Path,
    default_peers: list[int],
    listen_shooter: bool,
    listen_kw: dict[str, Any],
) -> None:
    """Incremental sync — add/remove accounts when JSON changes (no full reconnect)."""
    interval = _listen_hot_reload_interval_sec()
    retry_sec = _listen_failed_retry_sec()
    print(
        f"  Hot-reload: incremental sync every {interval}s"
        f" · failed-login retry cooldown {retry_sec}s",
        flush=True,
    )
    while True:
        await asyncio.sleep(interval)
        await _listen_sync_accounts(
            root=root,
            default_peers=default_peers,
            listen_shooter=listen_shooter,
            listen_kw=listen_kw,
        )


async def _watch_client_loop(
    cl: TelegramClient,
    acc_info: dict[str, Any],
    listen_kw: dict[str, Any],
) -> None:
    """Monitor disconnect/reconnect for one listener client."""
    accounts_doc = listen_kw["accounts_doc"]
    token = listen_kw["token"]
    acc_id = str(acc_info.get("id", "?"))
    profile = str(acc_info.get("detected_profile") or acc_info.get("profile_hint") or acc_id)
    pool_name = "shooter" if account_pool(acc_info) == "shooter" else "gcs"
    tag = "SHOOTER" if pool_name == "shooter" else "GCS"
    grace, reconnect_attempts, reconnect_delay, alert_cooldown, batch_min = _disconnect_watch_config()
    suppress_alerts = os.environ.get("TELEGRAM_DISCONNECT_ALERT", "1").strip().lower() in (
        "0",
        "false",
        "no",
        "off",
    )

    while True:
        try:
            await cl.run_until_disconnected()
        except asyncio.CancelledError:
            return
        except Exception:
            pass

        print(f"  [{tag}] {acc_id} — connection lost, reconnecting...", flush=True)

        if grace > 0:
            await asyncio.sleep(grace)

        if await _try_reconnect_listener_client(
            cl, reconnect_attempts, reconnect_delay, tag, acc_id
        ):
            print(f"  [{tag}] ✓ {acc_id} — back online", flush=True)
            continue

        print(f"⚠ [{tag}] DISCONNECTED: {acc_id} ({profile})", flush=True)

        if not suppress_alerts:
            now = time.time()
            last = _disconnect_last_alert.get(acc_id, 0.0)
            if now - last >= alert_cooldown:
                _disconnect_last_alert[acc_id] = now
                await _enqueue_disconnect_alert(
                    acc_info, profile, tag, token, accounts_doc, pool_name
                )
            else:
                left = int(alert_cooldown - (now - last))
                print(
                    f"  [{tag}] {acc_id} — alert skipped (cooldown {left}s)",
                    flush=True,
                )

        await asyncio.sleep(reconnect_delay)


async def run_listener_async() -> int:
    global _listen_watch_tasks
    _listen_watch_tasks.clear()
    _warm_account_status_cache()
    root = project_root()
    accounts_doc = load_json(accounts_json_path())
    brands_cfg = load_brands_config(accounts_doc)
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    if not token:
        print("TELEGRAM_BOT_TOKEN is empty", file=sys.stderr)
        return 2
    default_peers = parse_peer_ids(os.environ.get("TELEGRAM_OTP_PEER_IDS", "777000"), [777000])
    gcs_accounts = load_otp_accounts(accounts_doc, root, default_peers)
    listen_shooter = os.environ.get("TELEGRAM_LISTEN_SHOOTER", "1").strip().lower() not in (
        "0",
        "false",
        "no",
        "off",
    )
    shooter_accounts: list[dict[str, Any]] = []
    if listen_shooter:
        shooter_doc = load_shooter_doc()
        shooter_accounts = load_shooter_login_accounts(shooter_doc, root, default_peers)
    if not gcs_accounts and not shooter_accounts:
        print("No valid GCS / Shooter accounts found for listen.", file=sys.stderr)
        return 2
    loose = os.environ.get("TELEGRAM_OTP_LOOSE", "0").strip().lower() in ("1", "true", "yes", "on")
    template = (os.environ.get("TELEGRAM_OTP_MESSAGE_TEMPLATE") or "").strip()
    require_req = os.environ.get("TELEGRAM_REQUIRE_LOGIN_REQUEST", "1").strip().lower() not in (
        "0",
        "false",
        "no",
        "off",
    )
    # Second message hanya jika diaktifkan (default off — OTP sudah di template utama).
    send_copy_line = os.environ.get("TELEGRAM_OTP_SEND_COPY_LINE", "0").strip().lower() not in (
        "0",
        "false",
        "no",
        "off",
    )
    copy_line_template = (os.environ.get("TELEGRAM_OTP_COPY_LINE_TEMPLATE") or "{code}").strip()
    clients: list[tuple[TelegramClient, dict[str, Any]]] = []

    logging.getLogger("telethon").setLevel(logging.ERROR)

    conn_retries = _env_int("TELETHON_CONNECTION_RETRIES", 5, minimum=1)
    req_retries = _env_int("TELETHON_REQUEST_RETRIES", 5, minimum=1)

    sync_profile_on_listen = os.environ.get("TELEGRAM_SYNC_PROFILE_ON_LISTEN", "1").strip().lower() not in (
        "0",
        "false",
        "no",
        "off",
    )
    listen_kw = dict(
        accounts_doc=accounts_doc,
        brands_cfg=brands_cfg,
        token=token,
        loose=loose,
        template=template,
        require_req=require_req,
        send_copy_line=send_copy_line,
        copy_line_template=copy_line_template,
        sync_profile_on_listen=sync_profile_on_listen,
        conn_retries=conn_retries,
        req_retries=req_retries,
        clients=clients,
    )

    gcs_skipped: list[str] = []
    gcs_expired: list[str] = []
    gcs_active: list[str] = []
    gcs_sync: list[str] = []
    sh_skipped: list[str] = []
    sh_expired: list[str] = []
    sh_active: list[str] = []
    sh_sync: list[str] = []

    if gcs_accounts:
        print("\n" + "=" * 40, flush=True)
        print("  GCS ACCOUNTS", flush=True)
        print("=" * 40, flush=True)
        for acc in gcs_accounts:
            await _listen_start_account(
                acc,
                tag="GCS",
                skipped=gcs_skipped,
                expired=gcs_expired,
                active=gcs_active,
                profile_synced=gcs_sync,
                **listen_kw,
            )

    if shooter_accounts:
        print("\n" + "=" * 40, flush=True)
        print(f"  SHOOTER ACCOUNTS ({SHOOTER_DEFAULT_CURRENCY} only)", flush=True)
        print("=" * 40, flush=True)
        for acc in shooter_accounts:
            await _listen_start_account(
                acc,
                tag="SHOOTER",
                skipped=sh_skipped,
                expired=sh_expired,
                active=sh_active,
                profile_synced=sh_sync,
                **listen_kw,
            )

    all_expired = gcs_expired + sh_expired
    all_skipped = gcs_skipped + sh_skipped

    print("\n" + "=" * 40)
    print("  LISTENER SUMMARY")
    print("=" * 40)
    print(f"  GCS     · active {len(gcs_active)} / skip {len(gcs_skipped)} / expired {len(gcs_expired)}")
    if gcs_active:
        for a in gcs_active:
            print(f"    ✓ {a}")
    print(f"  SHOOTER · active {len(sh_active)} / skip {len(sh_skipped)} / expired {len(sh_expired)}")
    if sh_active:
        for a in sh_active:
            print(f"    ✓ {a}")
    if all_expired:
        print(f"  Expired : {len(all_expired)} (fill OTP column in Sheet — LIVE-LOGIN)")
        for e in all_expired:
            print(f"    ✗ {e}")
    if all_skipped:
        print(f"  Skipped : {len(all_skipped)} (not logged in)")
    if sync_profile_on_listen:
        print(
            f"  JSON sync: GCS {len(gcs_sync)} → accounts.json"
            f" | Shooter {len(sh_sync)} → shooteraccounts.json"
            f" | live profile updates via Telethon"
        )
    print("=" * 40 + "\n")

    # --- Send summary notification (forum topic System Status) ---
    notify_targets = login_status_notify_targets(accounts_doc)
    if notify_targets:
        summary_msg = build_listener_started_html(
            len(gcs_active),
            len(sh_active),
            all_expired,
            all_skipped,
            len(gcs_accounts),
            len(shooter_accounts),
        )
        send_login_status_message(token, summary_msg, accounts_doc)

    if not clients:
        print("ERROR: No listener started successfully.", file=sys.stderr)
        return 2

    global _disconnect_batch_lock, _disconnect_batch_flush_task
    _disconnect_batch_lock = asyncio.Lock()
    _disconnect_batch_flush_task = None
    _disconnect_batch_queue.clear()
    grace, reconnect_attempts, reconnect_delay, alert_cooldown, batch_min = _disconnect_watch_config()
    print(
        f"  Sheet status: queue only from LISTEN — LIVE-STATUS bulk-pushes to Google Sheet",
        flush=True,
    )
    print(
        f"  Disconnect policy: grace {grace}s · reconnect {reconnect_attempts}x/"
        f"{reconnect_delay}s · alert cooldown {alert_cooldown}s · batch ≥{batch_min}",
        flush=True,
    )

    tasks: list[asyncio.Task[None]] = []
    for cl, acc_info in clients:
        _listen_spawn_watch(listen_kw, cl, acc_info)
    tasks.extend(_listen_watch_tasks.values())
    if _listen_hot_reload_enabled():
        tasks.append(
            asyncio.create_task(
                _listen_hot_reload_loop(
                    root=root,
                    default_peers=default_peers,
                    listen_shooter=listen_shooter,
                    listen_kw=listen_kw,
                )
            )
        )
    else:
        print("  Hot-reload: OFF (set TELEGRAM_LISTEN_HOT_RELOAD=1 for auto new accounts)", flush=True)

    stop_stats = {
        "gcs_active": len(gcs_active),
        "shooter_active": len(sh_active),
        "gcs_total": len(gcs_accounts),
        "shooter_total": len(shooter_accounts),
    }
    stop_sent = False

    async def _notify_listener_stopped() -> None:
        nonlocal stop_sent
        if stop_sent or not _listener_stop_notify_enabled() or not notify_targets:
            return
        stop_sent = True
        msg = build_listener_stopped_html(
            stop_stats["gcs_active"],
            stop_stats["shooter_active"],
            stop_stats["gcs_total"],
            stop_stats["shooter_total"],
            reason="Lost Connection",
        )
        send_login_status_message(token, msg, accounts_doc)

    async def _shutdown_listener_tasks() -> None:
        for task in list(tasks):
            if not task.done():
                task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        for cl, acc_info in list(clients):
            acc_id = str(acc_info.get("id") or "")
            await _listen_disconnect_client(listen_kw, cl, acc_id)
        clients.clear()
        _listen_watch_tasks.clear()

    try:
        await asyncio.gather(*tasks)
    except (asyncio.CancelledError, KeyboardInterrupt):
        pass
    finally:
        await _shutdown_listener_tasks()
        await _notify_listener_stopped()
    return 0


def _purge_banned_accounts_enabled() -> bool:
    return os.environ.get("TELEGRAM_PURGE_BANNED_ACCOUNTS", "1").strip().lower() not in (
        "0",
        "false",
        "no",
        "off",
    )


def _purge_frozen_accounts_enabled() -> bool:
    """Remove confirmed Frozen accounts from JSON + session (re-login via Sheet Pending)."""
    return os.environ.get("TELEGRAM_PURGE_FROZEN_ACCOUNTS", "1").strip().lower() not in (
        "0",
        "false",
        "no",
        "off",
    )


def _status_is_banned(raw: str) -> bool:
    return str(raw or "").strip().lower() == "banned"


def _status_is_frozen(raw: str) -> bool:
    return str(raw or "").strip().lower() == "frozen"


def _delete_account_session_files(acc: dict[str, Any]) -> None:
    root = project_root()
    session_path = acc.get("session")
    if session_path:
        sp = Path(str(session_path))
        if not str(sp).endswith(".session"):
            sp = Path(str(sp) + ".session")
        if not sp.is_absolute():
            sp = root / sp
        _safe_unlink_session_file(sp)
        journal = Path(str(sp) + "-journal")
        _safe_unlink_session_file(journal)
    aid = str(acc.get("id") or "").strip()
    if aid:
        for pattern in (
            root / "telegram_session" / f"{aid}.session",
            root / "telegram_session" / "shooter" / f"{aid}.session",
        ):
            _safe_unlink_session_file(pattern)
            _safe_unlink_session_file(Path(str(pattern) + "-journal"))


def purge_account_from_json(
    account_id: str,
    pool: str,
    *,
    phone: str = "",
    reason: str = "Banned",
) -> bool:
    """Hapus akun Banned/Frozen dari otp_accounts / shooter_accounts + session file."""
    import sheets_sync

    list_key = "shooter_accounts" if str(pool or "").strip().lower() == "shooter" else "otp_accounts"
    path = _json_path_for_list_key(list_key)
    aid = str(account_id or "").strip()
    np = sheets_sync.norm_phone(phone)
    removed_row: dict[str, Any] | None = None

    def writer(data: dict[str, Any]) -> None:
        nonlocal removed_row
        lst = data.get(list_key)
        if not isinstance(lst, list):
            return
        kept: list[dict[str, Any]] = []
        for row in lst:
            if not isinstance(row, dict):
                kept.append(row)
                continue
            rid = str(row.get("id") or "").strip()
            rphone = sheets_sync.norm_phone(str(row.get("phone") or ""))
            if (aid and rid == aid) or (np and rphone and rphone == np):
                removed_row = row
                continue
            kept.append(row)
        data[list_key] = kept

    if not _mutate_json_file(path, writer) or removed_row is None:
        return False

    _delete_account_session_files(removed_row)
    label = aid or np or "?"
    print(f"  🗑 {reason} account removed from {path.name}: {label}", flush=True)
    return True


def purge_banned_account_from_json(
    account_id: str,
    pool: str,
    *,
    phone: str = "",
) -> bool:
    return purge_account_from_json(account_id, pool, phone=phone, reason="Banned")


def purge_frozen_account_from_json(
    account_id: str,
    pool: str,
    *,
    phone: str = "",
) -> bool:
    return purge_account_from_json(account_id, pool, phone=phone, reason="Frozen")


def _maybe_purge_account_from_json(
    account_id: str,
    pool: str,
    *,
    phone: str = "",
    status: str = "",
) -> None:
    st = str(status or "").strip()
    if _status_is_banned(st) and _purge_banned_accounts_enabled():
        purge_banned_account_from_json(account_id, pool, phone=phone)
    elif _status_is_frozen(st) and _purge_frozen_accounts_enabled():
        purge_frozen_account_from_json(account_id, pool, phone=phone)


def _queue_sheet_status(
    account_id: str,
    pool: str,
    status: str,
    note: str = "",
    *,
    phone: str = "",
    session_user: str = "",
    session_friday: str = "",
    allow_instant: bool | None = None,
    force_queue: bool = False,
) -> None:
    """Queue status for Sheet push → Status dropdown + Session Friday."""
    if not os.environ.get("GOOGLE_SHEET_ID", "").strip():
        return
    try:
        import sheets_sync

        sheets_sync.queue_status(
            project_root(),
            account_id,
            pool,
            status,
            note,
            phone=phone,
            session_user=session_user if session_user else (status if str(status or "").strip().lower() != "pending login" else ""),
            session_friday=session_friday,
            allow_instant=allow_instant,
            force_queue=force_queue,
        )
        st = str(session_user or status or "").strip()
        if st.lower() == "pending login":
            st = ""
        _maybe_purge_account_from_json(account_id, pool, phone=phone, status=st)
    except Exception:
        pass


def _classify_account_sheet_status(exc: BaseException) -> str:
    try:
        import sheets_sync

        return sheets_sync.classify_account_status(exc)
    except Exception:
        return "Expired"


def _safe_unlink_session_file(session_file: Path) -> None:
    """Best-effort hapus session tanpa membuat listener crash."""
    try:
        if session_file.is_file():
            session_file.unlink(missing_ok=True)
    except OSError:
        # Session bisa sedang di-lock SQLite. Abaikan agar proses lanjut.
        pass


def _session_friday_for_account_status(user_st: str, *, no_session: bool = False) -> str:
    """Session Friday mirrors account state — staff use this column as primary reference."""
    if no_session:
        return "Pending Login"
    st = str(user_st or "").strip()
    if st in ("Banned", "Frozen", "Expired", "Disconnected"):
        return st
    if st.lower() == "unknown":
        return "Disconnected"
    return "Active"


def _health_check_one_account(acc: dict[str, Any]) -> tuple[str, str, bool]:
    """Return (session_user, session_friday, frozen_confirmed)."""
    if not _session_file_ready(acc):
        return "", "Pending Login", False

    client, tmp_dir = _make_telethon_client_temp(acc)
    user_st = "Unknown"
    friday_st = "Active"
    frozen_confirmed = False
    try:
        client.connect()
        if not client.is_user_authorized():
            return "Expired", "Expired", False
        try:
            me = client.get_me()
            user_st = account_status_from_me(me)
            if user_st == "Frozen":
                frozen_confirmed = True
            elif user_st == "Active":
                # UI freeze (popup read-only) often keeps get_me().restricted=False.
                # Confirm via @SpamBot strict reply and/or Saved Messages probe.
                if frozen_spambot_probe_enabled():
                    sb = sync_probe_spambot_frozen(client)
                    if sb is True:
                        user_st = "Frozen"
                        frozen_confirmed = True
                if user_st == "Active" and frozen_ui_probe_enabled():
                    ui = sync_probe_frozen_ui(client)
                    if ui is True:
                        user_st = "Frozen"
                        frozen_confirmed = True
            friday_st = _session_friday_for_account_status(user_st)
        except Exception as e:
            user_st = _classify_account_sheet_status(e)
            friday_st = _session_friday_for_account_status(user_st)
    except Exception as e:
        user_st = _classify_account_sheet_status(e)
        friday_st = _session_friday_for_account_status(user_st, no_session=True)
    finally:
        try:
            result = client.disconnect()
            if inspect.isawaitable(result):
                loop = getattr(client, "loop", None)
                if loop is not None and not loop.is_running() and not loop.is_closed():
                    loop.run_until_complete(result)
        except Exception:
            pass
        try:
            import shutil as _shutil

            _shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass
    # Never push "Unknown" to Sheet during sync health.
    if str(user_st).strip().lower() == "unknown":
        user_st = "Disconnected"
    friday_st = _session_friday_for_account_status(user_st)
    return user_st, friday_st, frozen_confirmed


def _after_login_sync_status(acc: dict[str, Any], pool: str) -> tuple[str, str]:
    """
    After successful login:
      - Status dropdown → Ready (or Banned/Frozen if detected)
      - Session Friday → Active
      - OTP column cleared
    """
    root = project_root()
    acc_id = str(acc.get("id") or "?")
    phone = str(acc.get("phone") or "")
    print(f"  Recording Sheet status for {acc_id}...", flush=True)

    user_st, friday_st, _frozen_confirmed = _health_check_one_account(acc)
    try:
        import sheets_sync as _ss

        after_status = _ss.sheet_status_after_login_value()
    except Exception:
        after_status = "Ready"

    if user_st in ("Banned", "Frozen", "Expired", "Disconnected"):
        sheet_status = user_st
        friday_st = user_st
    else:
        sheet_status = after_status
        friday_st = "Active"

    _queue_sheet_status(
        acc_id,
        pool,
        sheet_status.lower(),
        phone=phone,
        session_user=sheet_status,
        session_friday=friday_st,
    )
    try:
        import sheets_sync

        if phone:
            if sheets_sync.instant_push_enabled():
                sheets_sync.push_status_instant(root, phone, sheet_status, friday_st)
            else:
                sheets_sync.update_sheet_status_column(root, phone, sheet_status)
            sheets_sync.clear_login_code_in_sheet(root, phone)
    except Exception:
        pass
    print(
        f"  Sheet: Status={sheet_status} | Session Friday={friday_st}",
        flush=True,
    )
    return sheet_status, friday_st


def _health_check_print_section(
    title: str,
    accounts: list[dict[str, Any]],
    pool_name: str,
    *,
    quiet: bool = False,
    token: str = "",
    accounts_doc: dict[str, Any] | None = None,
) -> dict[str, int]:
    """Print one GCS or Shooter block; return status counts."""
    counts: dict[str, int] = {}
    if not quiet:
        print(f"\n{'=' * 44}")
        print(f"  {title}  ({len(accounts)} account(s))")
        print(f"{'=' * 44}")
    if not accounts:
        if not quiet:
            print("  (none)")
        return counts

    for acc in accounts:
        acc_id = str(acc.get("id") or "?")
        phone = str(acc.get("phone") or "")
        profile = str(acc.get("profile_hint") or acc_id)
        user_st, friday_st, frozen_confirmed = _health_check_one_account(acc)
        counts[user_st] = counts.get(user_st, 0) + 1
        if not quiet:
            print(f"  · {acc_id} ({profile})")
            print(f"      Account Status : {user_st}")
            print(f"      Session Friday : {friday_st}")
        if user_st == "Active" and friday_st == "Active":
            prev_st = _known_account_status(acc)
            if prev_st.lower() in ("frozen", "expired", "disconnected"):
                try:
                    import sheets_sync

                    sheet_st = sheets_sync.sheet_status_after_login_value()
                except Exception:
                    sheet_st = "Ready"
                _mark_account_status_known(acc, "Active")
                _queue_sheet_status(
                    acc_id,
                    pool_name,
                    sheet_st.lower(),
                    f"recovered from {prev_st}",
                    phone=phone,
                    session_user=sheet_st,
                    session_friday="Active",
                    allow_instant=False,
                    force_queue=True,
                )
                if not quiet:
                    print(f"      ↺ recovered {acc_id}: {prev_st} → {sheet_st}/Active", flush=True)
            continue
        if not user_st and friday_st == "Active":
            continue
        check_st = user_st or friday_st
        if not _account_status_changed(acc, check_st):
            continue
        alert_st = user_st if user_st in ("Frozen", "Banned", "Expired", "Disconnected") else check_st
        if token and accounts_doc and alert_st in ("Frozen", "Banned", "Expired", "Disconnected"):
            _publish_account_status(
                acc,
                pool_name,
                alert_st,
                token=token,
                accounts_doc=accounts_doc,
                profile=profile,
                notify=True,
                frozen_confirmed=frozen_confirmed,
            )
        else:
            _mark_account_status_known(acc, check_st)
            _queue_sheet_status(
                acc_id,
                pool_name,
                user_st.lower() if user_st else "",
                profile,
                phone=phone,
                session_user=user_st,
                session_friday=friday_st,
                allow_instant=False,
            )
        time.sleep(0.25)

    if not quiet:
        parts = ", ".join(f"{k} {v}" for k, v in sorted(counts.items()))
        print(f"  ── Subtotal: {parts or '—'}")
    return counts


def run_health_check(pool: str = "all", target_id: str = "all", *, quiet: bool = False) -> int:
    """
    Brief connect to each account (temp session, safe with listen running).
    Output split: GCS and Shooter (not mixed).
    """
    logging.getLogger("telethon").setLevel(logging.WARNING)
    accounts = _load_pool_accounts(pool)
    accounts = _filter_pool_by_id(accounts, target_id)
    gcs_list = [a for a in accounts if account_pool(a) == "gcs"]
    sh_list = [a for a in accounts if account_pool(a) == "shooter"]

    if not gcs_list and not sh_list:
        if not quiet:
            print(f"No accounts for health-check (pool={pool}, id={target_id}).", file=sys.stderr)
        return 2

    _warm_account_status_cache()

    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    accounts_doc = load_json(accounts_json_path())

    if not quiet:
        print("\n-- Health-check (temp copy, listen may keep running) --")
        if frozen_spambot_probe_enabled():
            print("  @SpamBot probe: ON (health-check · strict · newest reply only)")
        if frozen_ui_probe_enabled():
            print("  Saved Messages probe: ON (health-check · secondary)")
        print("  Frozen alert: on CHANGE only · cooldown · never from LISTEN restart")

    total_gcs: dict[str, int] = {}
    total_sh: dict[str, int] = {}

    if pool in ("all", "gcs"):
        total_gcs = _health_check_print_section(
            "GCS ACCOUNTS", gcs_list, "gcs", quiet=quiet, token=token, accounts_doc=accounts_doc
        )
    if pool in ("all", "shooter"):
        total_sh = _health_check_print_section(
            "SHOOTER ACCOUNTS", sh_list, "shooter", quiet=quiet, token=token, accounts_doc=accounts_doc
        )

    merged: dict[str, int] = {}
    for bucket in (total_gcs, total_sh):
        for k, v in bucket.items():
            merged[k] = merged.get(k, 0) + v

    if quiet:
        parts = ", ".join(f"{k} {v}" for k, v in sorted(merged.items()))
        print(
            f"  ✓ Health-check done — GCS {len(gcs_list)} · Shooter {len(sh_list)} — {parts or 'all Active'}",
            flush=True,
        )
    else:
        print(f"\n{'=' * 44}")
        print("  HEALTH-CHECK SUMMARY")
        print(f"{'=' * 44}")
        if pool in ("all", "gcs"):
            g_parts = ", ".join(f"{k} {v}" for k, v in sorted(total_gcs.items()))
            print(f"  GCS     : {len(gcs_list)} checked — {g_parts or '—'}")
        if pool in ("all", "shooter"):
            s_parts = ", ".join(f"{k} {v}" for k, v in sorted(total_sh.items()))
            print(f"  SHOOTER : {len(sh_list)} checked — {s_parts or '—'}")
        print(f"{'=' * 44}\n")
    return 0


def _live_login_otp_poll_sec() -> float:
    return max(1.0, float(os.environ.get("TELEGRAM_SHEET_LOGIN_POLL_SEC", "2").strip() or "2"))


def _live_login_wait_log_interval_sec() -> float:
    return max(30.0, float(os.environ.get("TELEGRAM_LIVE_LOGIN_WAIT_LOG_SEC", "90").strip() or "90"))


def _live_login_idle_log_interval_sec() -> float:
    return max(60.0, float(os.environ.get("TELEGRAM_LIVE_LOGIN_IDLE_LOG_SEC", "300").strip() or "300"))


def _health_check_interval_sec() -> int:
    """0 = disabled in LIVE-STATUS loop. Default 43200 = 12 hours (2 shifts/day)."""
    raw = os.environ.get("TELEGRAM_SYNC_HEALTH_INTERVAL_SEC", "43200").strip()
    try:
        return max(0, int(float(raw)))
    except ValueError:
        return 43200


def _health_check_live_enabled() -> bool:
    if os.environ.get("TELEGRAM_SYNC_HEALTH_CHECK", "1").strip().lower() in (
        "0", "false", "no", "off",
    ):
        return False
    return _health_check_interval_sec() > 0


def _last_health_check_monotonic() -> float:
    try:
        st = load_json(state_json_path())
        return float(st.get("last_health_check_ts") or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _save_last_health_check_ts(ts: float | None = None) -> None:
    path = state_json_path()
    data = load_json(path)
    data["last_health_check_ts"] = ts if ts is not None else time.time()
    try:
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except OSError as e:
        logger.warning("cannot save health-check timestamp: %s", e)


def _health_check_due() -> bool:
    interval = _health_check_interval_sec()
    if interval <= 0:
        return False
    last = _last_health_check_monotonic()
    if last <= 0:
        return True
    return (time.time() - last) >= interval


def _health_check_next_due_ts() -> float | None:
    """Unix timestamp when the next scheduled health-check is due, or None if disabled."""
    if not _health_check_live_enabled():
        return None
    interval = _health_check_interval_sec()
    last = _last_health_check_monotonic()
    if last <= 0:
        return time.time()
    return last + interval


def _format_local_ts(ts: float) -> str:
    """Human-readable local time for ops banners (uses server timezone)."""
    return datetime.fromtimestamp(ts, tz=timezone.utc).astimezone().strftime("%d/%m/%Y %H:%M")


def _health_check_schedule_banner_lines() -> list[str]:
    """Startup lines for LIVE-STATUS: interval + next run time."""
    if not _health_check_live_enabled():
        return ["Scheduled health-check: off (TELEGRAM_SYNC_HEALTH_INTERVAL_SEC=0)"]
    interval = _health_check_interval_sec()
    every = _format_health_interval(interval)
    last = _last_health_check_monotonic()
    lines = [f"Full health-check every {every} (all accounts)"]
    if _health_check_due():
        if last <= 0:
            lines.append("Next health-check: now (first scheduled run)")
        else:
            lines.append(f"Next health-check: due now (last run {_format_local_ts(last)})")
    else:
        due_ts = _health_check_next_due_ts()
        if due_ts is not None:
            lines.append(f"Next health-check: {_format_local_ts(due_ts)} (last run {_format_local_ts(last)})")
    return lines


def _format_health_interval(sec: int) -> str:
    if sec <= 0:
        return "off"
    if sec % 86400 == 0:
        d = sec // 86400
        return f"{d} day(s)"
    if sec % 3600 == 0:
        return f"{sec // 3600} hour(s)"
    return f"{sec}s"


def _maybe_log_waiting_otp(acc_ids: list[str]) -> None:
    """Log 'waiting OTP' at most once per account per interval — no spam."""
    if not acc_ids:
        return
    now = time.time()
    gap = _live_login_wait_log_interval_sec()
    for aid in acc_ids:
        if not aid:
            continue
        last = _login_wait_otp_logged_at.get(aid, 0.0)
        if now - last >= gap:
            print(f"  · waiting OTP (5 digits) in Sheet for {aid} …", flush=True)
            _login_wait_otp_logged_at[aid] = now


def _run_sync_pull(
    root: Path,
    *,
    label: str = "Pull: Google Sheet → JSON",
    pending_only: bool | None = None,
    verbose: bool = True,
) -> int:
    """Import accounts from Telegram Acc tab. pending_only=True → hanya Status=Pending + phone baru."""
    import sheets_sync

    mode = "Pending-only (new phones)" if (pending_only if pending_only is not None else sheets_sync.pull_register_pending_only()) else "full"
    if verbose:
        print(f"\n── {label} [{mode}] ──")
    try:
        stats = sheets_sync.pull_from_sheet(
            root,
            lambda w: _mutate_json_file(accounts_json_path(), w),
            lambda w: _mutate_json_file(shooter_accounts_json_path(), w),
            pending_only=pending_only,
        )
        if verbose:
            print(
                f"  GCS     +{stats['gcs_added']} new, ~{stats['gcs_updated']} updated"
                f" (skip {stats['gcs_skipped']})"
            )
            renamed = stats.get("shooter_renamed", 0)
            migrated = stats.get("shooter_session_migrated", 0)
            cleaned = stats.get("shooter_session_cleaned", 0)
            rename_note = f", {renamed} owner→id renamed" if renamed else ""
            session_note = ""
            if migrated:
                session_note += f", {migrated} session file(s) renamed"
            if cleaned:
                session_note += f", {cleaned} orphan session(s) removed"
            print(
                f"  Shooter +{stats['shooter_added']} new, ~{stats['shooter_updated']} updated"
                f"{rename_note}{session_note} (skip {stats['shooter_skipped']})"
            )
        elif stats.get("gcs_added") or stats.get("shooter_added"):
            print(
                f"  ✓ registered: GCS +{stats['gcs_added']} · Shooter +{stats['shooter_added']}",
                flush=True,
            )
        return 0
    except Exception as e:
        print(f"✗ Pull failed: {e}", file=sys.stderr)
        return 1


def _run_sync_pull_after_login(root: Path) -> int:
    """After login: do not mass-update JSON (Pending-only pull = no-op for existing)."""
    return _run_sync_pull(
        root,
        label="Post-login JSON sync",
        pending_only=True,
        verbose=False,
    )


def _run_sync_push(root: Path, *, verbose: bool = True) -> tuple[int, int]:
    """Write Status dropdown & Session Friday to Google Sheet (queue delta)."""
    import sheets_sync

    try:
        default_peers = parse_peer_ids(os.environ.get("TELEGRAM_OTP_PEER_IDS", "777000"), [777000])
        raw_gcs = load_json(accounts_json_path())
        raw_sh = load_shooter_doc()
        gcs = load_otp_accounts(raw_gcs, root, default_peers)
        sh = load_shooter_login_accounts(raw_sh, root, default_peers)
        n = sheets_sync.push_status_to_sheet(root, gcs_accounts=gcs, shooter_accounts=sh)
        if verbose:
            print(f"  ✓ {n} row(s) updated in Sheet")
        return 0, n
    except Exception as e:
        print(f"✗ Push failed: {e}", file=sys.stderr)
        return 1, 0


def _run_sync_push_delta(root: Path, *, verbose: bool = True) -> tuple[int, int, int]:
    """Push queue delta only — no full baseline scan (saves API calls)."""
    import sheets_sync

    try:
        qpath = sheets_sync.status_queue_path(root)
        if not qpath.is_file() or not qpath.read_text(encoding="utf-8").strip():
            return 0, 0, 0

        default_peers = parse_peer_ids(os.environ.get("TELEGRAM_OTP_PEER_IDS", "777000"), [777000])
        raw_gcs = load_json(accounts_json_path())
        raw_sh = load_shooter_doc()
        gcs = load_otp_accounts(raw_gcs, root, default_peers)
        sh = load_shooter_login_accounts(raw_sh, root, default_peers)
        updated, queued = sheets_sync.push_status_delta(
            root, gcs_accounts=gcs, shooter_accounts=sh
        )
        if verbose:
            if queued:
                print(f"  ✓ {updated}/{queued} row(s) updated from queue")
            else:
                print("  · queue empty, skip API")
        return 0, updated, queued
    except Exception as e:
        print(f"✗ Push delta failed: {e}", file=sys.stderr)
        return 1, 0, 0


def run_sync_once(
    step: str = "all",
    *,
    pool: str = "all",
    account_id: str = "all",
    session_kill: str | None = None,
    keep_device: str = "FRIDAY_BO",
) -> int:
    """
    Satu siklus sync: pull → login → health → push (lalu exit).
    step: all | pull | login | health | push | sessions | init | once
    """
    root = project_root()
    step = (step or "all").strip().lower()
    if step == "once":
        step = "all"

    if step == "reconcile":
        return run_sync_reconcile()

    if step == "sessions" or session_kill:
        if session_kill:
            return run_terminate_session(pool, account_id, session_kill, keep_device=keep_device or None)
        return run_list_sessions(pool, account_id, keep_device=keep_device or "")

    if step == "init":
        import sheets_sync

        sheets_sync.ensure_sheet_tabs(root)
        print("✓ Sheet tabs ready (GCS + Shooter headers).")
        return 0

    if step in ("all", "pull"):
        if _run_sync_pull(root, label="1/4 Pull: Google Sheet → JSON", pending_only=False) != 0:
            return 1

    if step == "login":
        if _run_sync_pull(root, label="Import Sheet → JSON", pending_only=False) != 0:
            return 1

    if step in ("all", "login"):
        if _login_sheet_code_enabled():
            print(
                "\n── Login: skipped (Sheet mode) ──\n"
                "  Production uses LIVE-LOGIN: set Status=Pending, fill OTP column in Google Sheet.\n"
                "  No terminal login-all required.\n",
                flush=True,
            )
        else:
            login_hdr = "2/4 Login" if step == "all" else "Login"
            print(f"\n── {login_hdr}: new accounts only (no .session yet) ──")
            print("  (Already logged-in accounts are skipped automatically.)\n")
            rc_gcs = run_login_all()
            rc_sh = run_login_all_shooter()
            if rc_gcs != 0 or rc_sh != 0:
                print("⚠ Some logins failed — check output above.", file=sys.stderr)
            if _run_sync_pull_after_login(root) != 0:
                return 1

    health_on = os.environ.get("TELEGRAM_SYNC_HEALTH_CHECK", "1").strip().lower() not in (
        "0", "false", "no", "off",
    )
    if step in ("all", "health") and health_on:
        if step == "all":
            print("\n── 3/4 Health-check: detect Active / Banned / Frozen ──")
        run_health_check(pool, account_id)
    elif step == "health":
        print("Health-check disabled (TELEGRAM_SYNC_HEALTH_CHECK=0).", file=sys.stderr)
        if step == "health":
            return 0

    # Auto push after health (including `sync health`) — no separate `sync push` needed
    if step in ("all", "push", "health"):
        if step == "all":
            print("\n── 4/4 Push: status → Google Sheet ──")
        elif step == "health":
            print("\n── Auto push → Google Sheet ──")
        else:
            print("\n── Push: status → Google Sheet ──")
        rc_push, _updated_rows = _run_sync_push(root)
        if rc_push != 0:
            return rc_push

    if step == "all":
        print(
            "\n✓ Sync complete (pull + login + health + push). "
            "Restart `listen` once if new accounts were added."
        )
    elif step == "health":
        print("\n✓ Health-check + push to Sheet complete.")
    return 0


def run_sync_default(
    *,
    pool: str = "all",
    account_id: str = "all",
    keep_device: str = "FRIDAY_BO",
) -> int:
    """Default `sync`: pull Sheet → JSON only (login/status via production live services)."""
    root = project_root()
    print("\n── Sync: import Sheet → JSON ──")
    print("  (No terminal login — use production LIVE-PULL + LIVE-LOGIN + LIVE-STATUS.)\n")
    rc = 0
    if _run_sync_pull(root, label="Import Sheet → JSON") != 0:
        rc = 1
    print(
        "\n✓ Done.\n"
        "  New number in Sheet → LIVE-PULL registers JSON.\n"
        "  Set Status=Pending + fill OTP column → LIVE-LOGIN creates .session + updates J/K.\n"
        "  LISTEN hot-reload picks up account for daily OTP (/login).\n"
        "  LIVE-STATUS flushes status queue (Banned/Frozen/Disconnected…).\n"
        "  Start: .\\start_production.ps1 (5 windows)."
    )
    return rc


def run_sync_daemon(
    *,
    pool: str = "all",
    account_id: str = "all",
    keep_device: str = "FRIDAY_BO",
) -> int:
    """
    Optional periodic loop (not recommended) — may hit API limits & overwrite Sheet.
  """
    interval = _env_int("TELEGRAM_SYNC_INTERVAL_SEC", 600, minimum=60)
    print("=" * 50)
    print("  SYNC LOOP — optional (Ctrl+C to stop)")
    print(f"  ⚠ Every {interval}s: pull + login + health + push (may overwrite Sheet)")
    print("  Recommended: disable loop; use listen + instant push instead.")
    print("=" * 50)

    cycle = 0
    try:
        while True:
            cycle += 1
            ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            print(f"\n{'#' * 50}")
            print(f"  SYNC CYCLE #{cycle}  ·  {ts}")
            print(f"{'#' * 50}")
            rc = run_sync_once(
                "all",
                pool=pool,
                account_id=account_id,
                keep_device=keep_device,
            )
            if rc != 0:
                print(f"⚠ Cycle #{cycle} finished with error (rc={rc}).", file=sys.stderr)
            print(f"\n⏳ Idle {interval}s — next sync automatically (Ctrl+C to stop)...", flush=True)
            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n\n✓ Sync daemon stopped after {cycle} cycle(s).")
        return 0


def _live_login_skip_pull() -> bool:
    return os.environ.get("TELEGRAM_LIVE_LOGIN_SKIP_PULL", "1").strip().lower() not in (
        "0",
        "false",
        "no",
        "off",
    )


def run_sync_live_login() -> int:
    """Live login: Status=Pending -> send SMS once -> wait quietly for 5-digit OTP in Sheet."""
    if not os.environ.get("GOOGLE_SHEET_ID", "").strip():
        print("GOOGLE_SHEET_ID not set — live-login disabled.", file=sys.stderr)
        return 2
    root = project_root()
    interval_idle = _env_int("TELEGRAM_SYNC_LOGIN_INTERVAL_SEC", 60, minimum=20)
    interval_busy = _env_int("TELEGRAM_SYNC_LOGIN_FAST_INTERVAL_SEC", 5, minimum=2)
    fail_cooldown = _env_int("TELEGRAM_SHEET_LOGIN_FAIL_COOLDOWN_SEC", 600, minimum=60)
    otp_poll = _live_login_otp_poll_sec()

    trigger = os.environ.get("TELEGRAM_SHEET_LOGIN_TRIGGER_STATUS", "Pending").strip() or "Pending"
    print("=" * 56)
    print("  LIVE LOGIN — Sheet-triggered (no terminal login-all)")
    print(f"  OTP poll: {otp_poll}s (5-digit in Sheet) | idle: {interval_idle}s")
    print(f"  Trigger: Status = {trigger!r}")
    print("  Flow: Pending -> SMS once -> fill OTP -> Ready / Active (quiet while waiting)")
    print("=" * 56)

    cycle = 0
    last_idle_log = 0.0
    try:
        while True:
            cycle += 1
            now = time.time()
            import sheets_sync

            pending_phones = _pending_trigger_phones_from_sheet(root)
            if not pending_phones:
                if now - last_idle_log >= _live_login_idle_log_interval_sec():
                    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                    print(f"\n[Live Login] {ts} — no Status={trigger!r}", flush=True)
                    last_idle_log = now
                time.sleep(interval_idle)
                continue

            registered_early = _phones_registered_in_json(root, pending_phones)
            missing_early = pending_phones - registered_early

            if missing_early:
                ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                print(f"\n[Live Login] {ts} — register {len(missing_early)} new Pending row(s)", flush=True)
                if _run_sync_pull(
                    root,
                    label="Live Login: register new Pending row",
                    pending_only=True,
                    verbose=False,
                ) != 0:
                    print(f"⚠ Pull failed, retry in {interval_idle}s.", file=sys.stderr)
                    time.sleep(interval_idle)
                    continue

            pending = _collect_accounts_pending_login(root)
            registered = _phones_registered_in_json(root, pending_phones)
            missing = pending_phones - registered
            if missing:
                sample = ", ".join(sorted(missing)[:5])
                extra = f" (+{len(missing) - 5} more)" if len(missing) > 5 else ""
                print(
                    f"  ⚠ Pending in Sheet but not in JSON: {sample}{extra}",
                    flush=True,
                )

            if not pending:
                time.sleep(interval_busy)
                continue

            codes = sheets_sync.fetch_login_codes_by_phone(root, force=True)
            picked: tuple[str, dict[str, Any], str] | None = None
            preset = ""
            action = ""

            # 1) Session already OK → finalize Sheet only
            for json_key, acc, pool in pending:
                acc_id = str(acc.get("id") or "")
                if not acc_id or now < _login_fail_cooldown_until.get(acc_id, 0.0):
                    continue
                if _session_working(acc):
                    picked = (json_key, acc, pool)
                    preset = ""
                    action = "finalize"
                    break

            # 2) OTP (5 digits) in Sheet → login immediately
            if not picked:
                for json_key, acc, pool in pending:
                    acc_id = str(acc.get("id") or "")
                    if not acc_id or now < _login_fail_cooldown_until.get(acc_id, 0.0):
                        continue
                    if _session_working(acc):
                        continue
                    phone = sheets_sync.norm_phone(str(acc.get("phone") or ""))
                    code = codes.get(phone, "") if phone else ""
                    if code:
                        picked = (json_key, acc, pool)
                        preset = code
                        action = "otp"
                        break

            # 3) No OTP yet → send SMS once per account, then wait quietly
            if not picked:
                for json_key, acc, pool in pending:
                    acc_id = str(acc.get("id") or "")
                    if not acc_id or now < _login_fail_cooldown_until.get(acc_id, 0.0):
                        continue
                    if _session_working(acc):
                        continue
                    if acc_id in _login_awaiting_otp:
                        continue
                    picked = (json_key, acc, pool)
                    preset = ""
                    action = "sms"
                    break

            # 4) Already waiting for OTP — silent poll (log at most every 90s)
            if not picked:
                waiting_ids = [
                    str(acc.get("id") or "")
                    for _, acc, _ in pending
                    if str(acc.get("id") or "") in _login_awaiting_otp
                    and not _session_working(acc)
                ]
                if waiting_ids:
                    _maybe_log_waiting_otp([i for i in waiting_ids if i])
                    time.sleep(otp_poll)
                    continue
                if all(
                    now < _login_fail_cooldown_until.get(str(acc.get("id") or ""), 0.0)
                    for _, acc, _ in pending
                    if str(acc.get("id") or "")
                ):
                    time.sleep(interval_busy)
                    continue
                time.sleep(otp_poll)
                continue

            json_key, acc, pool = picked
            acc_id = str(acc.get("id") or "?")
            label = "SHOOTER" if pool == "shooter" else "GCS"
            phone = str(acc.get("phone") or "")
            ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

            if action == "finalize":
                print(f"\n[Live Login] {ts} -> finalize {acc_id} ({label})", flush=True)
                pool_name = "shooter" if pool == "shooter" else "gcs"
                _after_login_sync_status(acc, pool_name)
                _run_sync_push_delta(root, verbose=False)
                _run_sync_pull_after_login(root)
                _login_awaiting_otp.pop(acc_id, None)
                _login_wait_otp_logged_at.pop(acc_id, None)
                notify_live_login_event(acc, "finalize", label=label)
                print(f"  ✓ {acc_id} Sheet updated (Ready / Active).", flush=True)
                time.sleep(interval_busy)
                continue

            if action == "otp":
                print(f"\n[Live Login] {ts} -> OTP detected → login {acc_id} ({label})", flush=True)
                notify_live_login_event(acc, "otp", label=label)
            elif action == "sms":
                print(
                    f"\n[Live Login] {ts} -> SMS request {acc_id} ({label}) — fill OTP column when received",
                    flush=True,
                )
                _login_awaiting_otp[acc_id] = now
                notify_live_login_event(acc, "sms", label=label)

            _apply_sheet_login_fields(acc, root)
            ok, fail_reason = _login_single_account(
                acc,
                json_key,
                label,
                preset_code=preset,
                quiet=(action == "sms"),
                live_notify=True,
            )
            if not ok and _session_working(acc):
                ok = True
                fail_reason = ""
                pool_name = "shooter" if pool == "shooter" else "gcs"
                _after_login_sync_status(acc, pool_name)
                _run_sync_push_delta(root, verbose=False)
                print(
                    f"  ✓ {acc_id} session verified (recovered — was marked failed incorrectly)",
                    flush=True,
                )
            if ok:
                print(f"  ✓ {acc_id} session ready — LISTEN hot-reload will pick it up.", flush=True)
                _login_fail_cooldown_until.pop(acc_id, None)
                _login_awaiting_otp.pop(acc_id, None)
                _login_wait_otp_logged_at.pop(acc_id, None)
                profile = str(acc.get("profile_hint") or acc_id)
                notify_live_login_event(
                    acc,
                    "success",
                    label=label,
                    profile=profile,
                )
                _run_sync_pull_after_login(root)
            else:
                if _session_file_ready(acc):
                    ok = True
                    fail_reason = ""
                    pool_name = "shooter" if pool == "shooter" else "gcs"
                    _after_login_sync_status(acc, pool_name)
                    _run_sync_push_delta(root, verbose=False)
                    _login_fail_cooldown_until.pop(acc_id, None)
                    _login_awaiting_otp.pop(acc_id, None)
                    print(
                        f"  ✓ {acc_id} session file OK — Sheet updated (recovered from verify error)",
                        flush=True,
                    )
                    notify_live_login_event(
                        acc,
                        "success",
                        label=label,
                        detail="Recovered after verify glitch",
                    )
                    _run_sync_pull_after_login(root)
                else:
                    _login_fail_cooldown_until[acc_id] = now + fail_cooldown
                    _login_awaiting_otp.pop(acc_id, None)
                    detail = fail_reason or "login verification failed"
                    print(f"  ✗ {acc_id} failed — {detail} — cooldown {fail_cooldown}s", file=sys.stderr)
                    notify_live_login_event(
                        acc,
                        "failed",
                        label=label,
                        detail=f"{detail} (cooldown {fail_cooldown}s)",
                    )

            time.sleep(interval_busy if ok else min(interval_busy, otp_poll))
    except KeyboardInterrupt:
        print(f"\n\n✓ Live login stopped after {cycle} cycle(s).")
        return 0


def run_sync_live_pull() -> int:
    """
    Live pull: register NEW accounts only when Sheet Status = Pending.
    Does not update existing JSON rows (avoids junk re-import every cycle).
    """
    root = project_root()
    interval = _env_int("TELEGRAM_SYNC_PULL_INTERVAL_SEC", 90, minimum=30)
    trigger = os.environ.get("TELEGRAM_SHEET_LOGIN_TRIGGER_STATUS", "Pending").strip() or "Pending"
    print("=" * 52)
    print("  LIVE PULL — Pending -> JSON (new phones only)")
    print(f"  Trigger: Status = {trigger!r} + phone not in JSON yet")
    print(f"  Interval: {interval}s (Ctrl+C to stop)")
    print("  Existing accounts are never modified by this service.")
    print("=" * 52)

    cycle = 0
    try:
        while True:
            cycle += 1
            ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            print(f"\n[Live Pull #{cycle}] {ts}")
            rc = _run_sync_pull(
                root,
                label="Live Pull",
                pending_only=True,
            )
            if rc != 0:
                err_hint = " (429 quota — increase TELEGRAM_SYNC_PULL_INTERVAL_SEC)" if rc == 1 else ""
                print(
                    f"⚠ Live pull failed (rc={rc}){err_hint}, retrying in {interval}s.",
                    file=sys.stderr,
                )
            print(f"⏳ Waiting {interval}s...", flush=True)
            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n\n✓ Live pull stopped after {cycle} cycle(s).")
        return 0


def run_sync_live_status(
    *,
    pool: str = "all",
    account_id: str = "all",
) -> int:
    """
    Live status: queue delta push + scheduled full health-check (default every 12 hours).
    """
    if pool != "all" or account_id != "all":
        print("⚠ live-status ignores --pool/--id; this mode pushes global delta.", file=sys.stderr)

    interval = _env_int("TELEGRAM_SYNC_STATUS_INTERVAL_SEC", 120, minimum=30)
    hc_interval = _health_check_interval_sec()
    hc_on = _health_check_live_enabled()
    print("=" * 56)
    print("  LIVE STATUS — queue -> Google Sheet")
    print(f"  Delta push every {interval}s")
    if hc_on:
        for line in _health_check_schedule_banner_lines():
            print(f"  {line}")
    else:
        print("  Scheduled health-check: off (TELEGRAM_SYNC_HEALTH_INTERVAL_SEC=0)")
    print("=" * 56)

    cycle = 0
    try:
        while True:
            cycle += 1
            root = project_root()

            if hc_on and _health_check_due():
                ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                print(f"\n[Live Status] {ts} — scheduled health-check starting …", flush=True)
                hc_rc = run_health_check(quiet=True)
                if hc_rc == 0:
                    _save_last_health_check_ts()
                    nxt = _health_check_next_due_ts()
                    if nxt is not None:
                        print(
                            f"  Next health-check scheduled: {_format_local_ts(nxt)}",
                            flush=True,
                        )
                else:
                    print("  ⚠ Health-check skipped or failed.", file=sys.stderr)

            rc_push, updated_rows, queued = _run_sync_push_delta(root, verbose=False)
            if rc_push != 0:
                print(f"⚠ Push status failed (rc={rc_push}), retrying in {interval}s.", file=sys.stderr)
            elif queued > 0:
                ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                if updated_rows > 0:
                    print(f"[Live Status #{cycle}] {ts} -> {updated_rows}/{queued} row(s) updated")
                else:
                    print(
                        f"[Live Status #{cycle}] {ts} -> queue {queued}, skip (already matches Sheet)"
                    )
            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n\n✓ Live status stopped after {cycle} cycle(s).")
        return 0


def run_sync_reconcile() -> int:
    """Laporan akun di JSON tapi tidak di Sheet (dan sebaliknya)."""
    import sheets_sync

    root = project_root()
    if not os.environ.get("GOOGLE_SHEET_ID", "").strip():
        print("GOOGLE_SHEET_ID not set.", file=sys.stderr)
        return 2
    default_peers = parse_peer_ids(os.environ.get("TELEGRAM_OTP_PEER_IDS", "777000"), [777000])
    raw_gcs = load_json(accounts_json_path())
    gcs = load_otp_accounts(raw_gcs, root, default_peers)
    raw_sh = load_shooter_doc()
    shooter = load_shooter_login_accounts(raw_sh, root, default_peers)
    missing_sheet, missing_json = sheets_sync.reconcile_json_vs_sheet(
        root, gcs_accounts=gcs, shooter_accounts=shooter
    )

    print("=" * 56)
    print("  RECONCILE — JSON vs Google Sheet (Telegram Acc)")
    print("=" * 56)
    print(f"\n  JSON total     : {len(gcs) + len(shooter)} account(s)")
    print(f"  Missing Sheet  : {len(missing_sheet)} (ada di JSON, tidak di Sheet)")
    print(f"  Missing JSON   : {len(missing_json)} (ada di Sheet, tidak di JSON)")

    if missing_sheet:
        print("\n── Tambahkan baris ini ke Google Sheet ──")
        by_brand: dict[str, list[dict[str, str]]] = {}
        for row in missing_sheet:
            b = row.get("brand") or row.get("pool") or "?"
            by_brand.setdefault(b, []).append(row)
        for brand in sorted(by_brand, key=lambda x: x.lower()):
            rows = sorted(by_brand[brand], key=lambda r: r.get("id", ""))
            print(f"\n  [{brand}] {len(rows)} account(s)")
            for r in rows[:50]:
                print(f"    · {r['id']:22} {r['phone']:16} {r['profile']}")
            if len(rows) > 50:
                print(f"    … +{len(rows) - 50} more")

    if missing_json:
        print("\n── Ada di Sheet tapi tidak di JSON (Pending pull / junk?) ──")
        for r in missing_json[:40]:
            print(
                f"    · {r['phone']:16} {r['name']!r:20} "
                f"status={r['status']} group={r['group']}"
            )
        if len(missing_json) > 40:
            print(f"    … +{len(missing_json) - 40} more")

    if not missing_sheet and not missing_json:
        print("\n  ✓ JSON dan Sheet selaras (by phone).")
    elif missing_sheet:
        print(
            "\n  → Tambah baris di Sheet, lalu set Status=Pending hanya untuk login baru.",
            flush=True,
        )
    print()
    return 0


def run_sync(
    step: str | None = None,
    *,
    pool: str = "all",
    account_id: str = "all",
    session_kill: str | None = None,
    keep_device: str = "FRIDAY_BO",
) -> int:
    """Default: pull + login. Sheet live-update via listen. `sync loop` = loop opsional."""
    if step is None:
        return run_sync_default(pool=pool, account_id=account_id, keep_device=keep_device)
    if step == "loop":
        return run_sync_daemon(pool=pool, account_id=account_id, keep_device=keep_device)
    if step == "live":
        return run_sync_live_pull()
    if step == "live-login":
        return run_sync_live_login()
    if step == "live-status":
        return run_sync_live_status(pool=pool, account_id=account_id)
    if step == "reconcile":
        return run_sync_reconcile()
    return run_sync_once(
        step,
        pool=pool,
        account_id=account_id,
        session_kill=session_kill,
        keep_device=keep_device,
    )


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Telegram OTP all-in-one.",
        epilog="Tip: use `sync` for Sheet + new logins + status. See COMMANDS.txt.",
    )
    sub = ap.add_subparsers(dest="command", required=True)

    p_sync = sub.add_parser(
        "sync",
        help="Smart hub: Sheet↔JSON, login new accounts, push status, manage sessions.",
    )
    p_sync.add_argument(
        "step",
        nargs="?",
        default=None,
        choices=[
            "once", "all", "loop", "live", "live-login", "live-status", "reconcile",
            "pull", "login", "health", "push", "sessions", "init",
        ],
        help="reconcile=JSON vs Sheet report. live=Sheet->JSON. live-status=delta push.",
    )
    p_sync.add_argument("--pool", choices=["gcs", "shooter", "all"], default="all")
    p_sync.add_argument("--id", dest="account_id", default="all", help="For sessions: id/brand partial.")
    p_sync.add_argument(
        "--kill",
        dest="session_kill",
        default=None,
        metavar="REF",
        help="Terminate session: index number, hash, or 'others' (keep FRIDAY_BO).",
    )
    p_sync.add_argument("--keep-device", dest="keep_device", default="FRIDAY_BO")

    sub.add_parser("bot", help="Run bot polling (/start, /ping).")
    sub.add_parser("login-all", help="Bootstrap login for all otp_accounts (GCS).")
    sub.add_parser("login-all-shooter", help="Login shooter_accounts + sync profile_hint from Telegram.")
    sub.add_parser(
        "listen",
        help="OTP listener for GCS + Shooter (separate logs; shooter MYR topic only).",
    )
    p_notify = sub.add_parser("notify", help="Send a manual message via bot.")
    p_notify.add_argument("message", help="Message text")
    p_notify.add_argument("-a", "--account", default=None, help="Target account id")
    p_notify.add_argument("--all", action="store_true", help="send to all registered chat ids")

    p_term = sub.add_parser(
        "terminate-other-sessions",
        help="Terminate all Telegram sessions except the current one for OTP accounts.",
    )
    p_term.add_argument(
        "account_id",
        help="Account id (e.g. SH_VENAN_01, STMY_CS01) or 'all' for every account.",
    )
    p_term.add_argument(
        "--pool", choices=["gcs", "shooter", "all"], default="all",
        help="Account pool to search (default: all).",
    )

    p_ls = sub.add_parser(
        "list-sessions",
        help="List all active Telegram sessions for an OTP account with device/IP details.",
    )
    p_ls.add_argument(
        "--id", dest="account_id", default="all",
        help="Account id, label, or name (e.g. STMY_LINA, stmy, Venan) or 'all'.",
    )
    p_ls.add_argument(
        "--pool", choices=["gcs", "shooter", "all"], default="all",
        help="Account pool to search (default: all).",
    )
    p_ls.add_argument(
        "--keep-device", dest="keep_device", default="FRIDAY_BO",
        metavar="DEVICE",
        help="Device name to mark as protected in the listing (default: FRIDAY_BO).",
    )

    p_ts = sub.add_parser(
        "terminate-session",
        help="Terminate a specific session by index (from list-sessions) or hash. Use 'others' to terminate all non-current.",
    )
    p_ts.add_argument(
        "--id", dest="account_id", required=True,
        help="Account id, label, or name (e.g. SH_VENAN_01, venan).",
    )
    p_ts.add_argument(
        "--session", dest="session_ref", required=True,
        help="Session index (1, 2, 3…), hash value, or 'others' to terminate all non-current sessions.",
    )
    p_ts.add_argument(
        "--pool", choices=["gcs", "shooter", "all"], default="all",
        help="Account pool to search (default: all).",
    )
    p_ts.add_argument(
        "--keep-device", dest="keep_device", default="FRIDAY_BO",
        metavar="DEVICE",
        help="Device name to always protect from termination (default: FRIDAY_BO). Use '' to disable.",
    )
    return ap


def main() -> int:
    _configure_stdio_utf8()
    _configure_runtime_warnings()
    logging.basicConfig(format="%(asctime)s %(levelname)s %(name)s %(message)s", level=logging.INFO)
    # Avoid spam "Task was destroyed but it is pending!" on forced stop on Windows.
    logging.getLogger("asyncio").setLevel(logging.CRITICAL)
    # Redam traceback internal Telethon yang sering muncul saat paket jaringan rusak/transient.
    # Listener has its own reconnect; detailed logs here are just noise.
    logging.getLogger("telethon.network.mtprotosender").setLevel(logging.CRITICAL)
    logging.getLogger("telethon.extensions.binaryreader").setLevel(logging.CRITICAL)
    load_dotenv(project_root() / ".env")
    if sys.platform == "win32" and sys.version_info < (3, 14):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    args = build_parser().parse_args()
    if args.command == "sync":
        return run_sync(
            getattr(args, "step", None),
            pool=args.pool,
            account_id=args.account_id,
            session_kill=getattr(args, "session_kill", None),
            keep_device=getattr(args, "keep_device", "FRIDAY_BO"),
        )
    if args.command == "bot":
        return run_bot()
    if args.command == "login-all":
        return run_login_all()
    if args.command == "login-all-shooter":
        return run_login_all_shooter()
    if args.command == "listen":
        return asyncio.run(run_listener_async())
    if args.command == "notify":
        return run_notify(args.message, args.account, args.all)
    if args.command == "terminate-other-sessions":
        return run_terminate_other_sessions(args.pool, args.account_id)
    if args.command == "list-sessions":
        return run_list_sessions(args.pool, args.account_id, keep_device=args.keep_device or "")
    if args.command == "terminate-session":
        return run_terminate_session(
            args.pool, args.account_id, args.session_ref,
            keep_device=args.keep_device or None,
        )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

