"""
Google Sheets ↔ accounts.json / shooteraccounts.json
Main tab: "Telegram Acc" (operational sheet format).
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

# --- Header aliases (case-insensitive) ---
_HEADER_ALIASES: dict[str, frozenset[str]] = {
    "device_id": frozenset({"device_id", "deviceid"}),
    "location": frozenset({"location"}),
    "group": frozenset({"group"}),
    "user": frozenset({"user", "staff", "owner", "shooter_owner"}),
    "channel": frozenset({"channel"}),
    "acc_name": frozenset({"acc_name", "accname", "account_name", "profile_hint", "profile", "name"}),
    "phone": frozenset({"phone", "phone_number", "number"}),
    "telco": frozenset({"telco"}),
    # Single Status column (dropdown): Pending=login trigger; script writes Ready/Banned/Frozen/…
    "status": frozenset({"status", "state", "feeding_status", "feeding"}),
    # Legacy — removed from Sheet; read-only fallback if column still exists
    "session_user": frozenset({
        "session_user",
        "sessionuser",
        "account_status",
        "accountstatus",
    }),
    "session_friday": frozenset({"session_friday", "sessionfriday", "friday_session"}),
    # legacy tabs
    "pool": frozenset({"pool", "type", "account_type"}),
    "id": frozenset({"id", "account_id", "account"}),
    "profile_hint": frozenset({"profile_hint"}),
    "api_id": frozenset({"api_id", "apiid"}),
    "api_hash": frozenset({"api_hash", "apihash"}),
    # 2FA / cloud password (any column; header e.g. "2FA")
    "password": frozenset({
        "password",
        "2fa",
        "twofa",
        "two_fa",
        "2fa_password",
        "twofa_password",
        "cloud_password",
        "cloud_pass",
        "telegram_2fa",
        "telegram_password",
    }),
    "brand": frozenset({"brand"}),
    "owner": frozenset({"owner"}),
    "enabled": frozenset({"enabled", "active"}),
    "notify_account": frozenset({"notify_account", "notify"}),
    "session": frozenset({"session", "session_path"}),
    "notes": frozenset({"notes", "note", "remark", "remarks"}),
    # Staff fills this while backend waits during Telethon login (sync live-login / login-all)
    "login_code": frozenset({
        "login_code",
        "logincode",
        "login_otp",
        "telethon_code",
        "otp_code",
        "otp",
        "code",
        "verification_code",
    }),
}


def _normalize_sheet_status_value(raw: str) -> str:
    return re.sub(r"\s+", " ", str(raw or "").strip().lower())


def sheet_status_is_login_trigger(raw: str) -> bool:
    """Status = Pending triggers LIVE-LOGIN (staff sets via dropdown)."""
    trigger = os.environ.get("TELEGRAM_SHEET_LOGIN_TRIGGER_STATUS", "Pending").strip()
    return _normalize_sheet_status_value(raw) == _normalize_sheet_status_value(trigger)


def sheet_status_after_login_value() -> str:
    """Status after successful login (default Ready)."""
    return os.environ.get("TELEGRAM_SHEET_STATUS_AFTER_LOGIN", "Ready").strip() or "Ready"


def pull_register_pending_only() -> bool:
    """When True, pull only adds NEW rows where Status = Pending (production default)."""
    v = os.environ.get("TELEGRAM_SYNC_PULL_PENDING_ONLY", "1").strip().lower()
    return v not in ("0", "false", "no", "off")


def effective_row_status(row: dict[str, str]) -> str:
    """Account status from Sheet — Status column only (legacy Account Status as fallback)."""
    return str(row.get("status") or row.get("session_user") or "").strip()


def _status_column_index(headers: list[str]) -> int | None:
    col = _col_index(headers, "status")
    if col is not None:
        return col
    return _col_index(headers, "session_user")


_OWNER_FIX: dict[str, str] = {
    "venus": "VENNUS",
    "vennus": "VENNUS",
    "liyun": "LIHYUN",
    "lihyun": "LIHYUN",
    "eudora": "EUDORA",
    "fanie": "FANIE",
    "wai": "WAI",
    "sheva": "SHEVA",
    "kelly": "KELLY",
    "aldo": "ALDO",
    "indri": "INDRI",
    "rinto": "RINTO",
    "rizkyr": "RIZKYR",
    "venan": "VENAN",
    "widya": "WIDYA",
}


def _norm_header(h: str) -> str | None:
    key = re.sub(r"[^a-z0-9_]+", "_", str(h or "").strip().lower()).strip("_")
    for canonical, aliases in _HEADER_ALIASES.items():
        if key in aliases:
            return canonical
    return None


def _row_dict(headers: list[str], values: list[Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for i, h in enumerate(headers):
        canon = _norm_header(h)
        if not canon:
            continue
        val = values[i] if i < len(values) else ""
        out[canon] = str(val or "").strip()
    return out


def _truthy(s: str) -> bool:
    return str(s or "").strip().lower() not in ("0", "false", "no", "off", "")


_CURRENCY_CODES = frozenset({
    "MYR", "SGD", "USD", "USC", "KHR", "IDR", "THB", "VND", "PHP", "INR",
    "CNY", "JPY", "KRW", "MMK", "BRL", "EUR", "GBP", "AUD",
})


def is_currency_code(value: str) -> bool:
    return str(value or "").strip().upper() in _CURRENCY_CODES


# Sheet Device ID: CURRENCY-CODE[-suffix]  e.g. MYR-SB, SGD-FW-003
# Currency = part 1 (MYR, SGD, USC). Brand code = part 2.
_DEVICE_BRAND_CODES: dict[str, str] = {
    "SB": "SBMY",
    "ST": "STMY",
    "JM": "JMMY",
    "FW": "FWSG",
    "WB": "WBSG",
    "M24": "M24SG",
}


def parse_device_id(device_id: str) -> tuple[str, str]:
    """Parse 'MYR-SB main user geri' → currency='MYR', brand_code='SB'."""
    raw = str(device_id or "").strip()
    if not raw:
        return "", ""
    head = raw.split()[0]
    parts = [p.strip().upper() for p in head.split("-") if p.strip()]
    if len(parts) >= 2:
        return parts[0], parts[1]
    if len(parts) == 1:
        return "", parts[0]
    return "", ""


def resolve_device_brand_code(
    code: str,
    *,
    currency: str = "",
    brands_cfg: dict[str, dict[str, Any]] | None = None,
) -> str | None:
    """Map device brand code (SB, ST, M24, …) → full brand key (SBMY, M24SG, …)."""
    c = str(code or "").strip().upper()
    if not c:
        return None
    mapped = _DEVICE_BRAND_CODES.get(c)
    if mapped:
        if brands_cfg and currency:
            cfg = brands_cfg.get(mapped, {})
            cur = str(cfg.get("currency") or "").strip().upper()
            if cur and cur != currency.upper():
                mapped = None
            else:
                return mapped
        elif mapped:
            return mapped
    if not brands_cfg:
        return None
    cur_u = currency.upper().strip()
    candidates: list[str] = []
    for bk, bv in brands_cfg.items():
        if not isinstance(bv, dict):
            continue
        bcur = str(bv.get("currency") or "").strip().upper()
        if cur_u and bcur and bcur != cur_u:
            continue
        if bk == c or bk.startswith(c) or c in bk:
            candidates.append(bk)
    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]
    candidates.sort(key=lambda x: (len(x), x))
    for bk in candidates:
        if bk.startswith(c):
            return bk
    return candidates[0]


_ID_PREFIX_BRAND_ALIASES: dict[str, str] = {
    "SEABET99KH": "SB99KH",
    "SEABET99": "SB99KH",
    "SEABETKH": "SBKH",
    "SEABETCS99": "SBKH",
    "SEABETKHCS01": "SBKH",
    "SEABETKHCS2": "SBKH",
    "SEABETKHCS5": "SBKH",
    "17WIN168": "17WIN168KH",
    "UWON29": "UW29KH",
    "UWKH29": "UW29KH",
}


def resolve_brand_from_id(
    account_id: str,
    brands_cfg: dict[str, dict[str, Any]] | None = None,
) -> str | None:
    """Resolve brand from account id prefix; prefer full keys in brands_cfg."""
    aid = str(account_id or "").strip().upper()
    if not aid or aid in ("GCS", "SH", "UNKNOWN"):
        return None
    pref = aid.split("_", 1)[0] if "_" in aid else aid
    pref = _ID_PREFIX_BRAND_ALIASES.get(pref, pref)
    if is_currency_code(pref):
        return None
    if brands_cfg:
        if pref in brands_cfg:
            return pref
        best = ""
        for bk in brands_cfg:
            bu = str(bk).strip().upper()
            if aid == bu or aid.startswith(f"{bu}_"):
                if len(bu) > len(best):
                    best = bu
        if best:
            return best
        for bk in sorted(brands_cfg, key=lambda x: len(str(x)), reverse=True):
            bu = str(bk).strip().upper()
            if bu.startswith(pref) and len(bu) > len(pref):
                return bu
    if len(pref) >= 3:
        return pref
    return None


def infer_gcs_brand(
    *,
    device_id: str = "",
    acc_name: str = "",
    account_id: str = "",
    brand: str = "",
    brands_cfg: dict[str, dict[str, Any]] | None = None,
) -> str | None:
    """
    Brand for GCS — Device ID (MYR-SB → SBMY) for new rows; id/brand for existing.
    """
    b = str(brand or "").strip().upper()
    if b and not is_currency_code(b):
        if not brands_cfg or b in brands_cfg:
            return b

    resolved = resolve_brand_from_id(account_id, brands_cfg)
    if resolved:
        return resolved

    currency, code = parse_device_id(device_id)
    if code and currency:
        resolved = resolve_device_brand_code(code, currency=currency, brands_cfg=brands_cfg)
        if resolved:
            return resolved
        code_u = code.upper()
        cur_u = currency.upper()
        if brands_cfg:
            for bk, bv in brands_cfg.items():
                if not isinstance(bv, dict):
                    continue
                bu = str(bk).strip().upper()
                bcur = str(bv.get("currency") or "").strip().upper()
                if bcur and bcur != cur_u:
                    continue
                if bu == code_u or bu.startswith(f"{code_u}") or code_u.startswith(bu):
                    return bu
    return None


def norm_phone(raw: str) -> str:
    """60123456789 → +60123456789; 08xx → +628xx (Indonesia); 01xx → +601xx (Malaysia)."""
    d = re.sub(r"\D", "", str(raw or ""))
    if not d:
        return ""
    if d.startswith("00"):
        d = d[2:]
    if d.startswith("0") and len(d) >= 9:
        if d.startswith("08"):
            d = "62" + d[1:]
        elif d.startswith("01"):
            d = "60" + d[1:]
        else:
            d = d.lstrip("0") or d
    return "+" + d


# --- In-memory cache: avoid Google Sheets 429 (read quota per minute) ---
_SHEET_TAB_CACHE: dict[str, tuple[float, list[str], list[list[str]]]] = {}


def invalidate_sheet_cache() -> None:
    _SHEET_TAB_CACHE.clear()


def _sheet_read_cache_sec() -> float:
    raw = os.environ.get("TELEGRAM_SHEET_READ_CACHE_SEC", "120").strip()
    try:
        return max(5.0, float(raw))
    except ValueError:
        return 120.0


def read_telegram_acc_tab(root: Path, *, force: bool = False) -> tuple[list[str], list[list[str]]]:
    """Cached read of tab Telegram Acc. Use force=True for pull/register (must be fresh)."""
    if not _sheet_id() or not use_telegram_acc_format():
        return [], []
    tab = _tab_telegram()
    cache_key = f"{_sheet_id()}:{tab}"
    now = time.time()
    if not force:
        hit = _SHEET_TAB_CACHE.get(cache_key)
        if hit and (now - hit[0]) < _sheet_read_cache_sec():
            return hit[1], hit[2]
    wb = open_workbook(root)
    headers, lines = _read_tab_raw(wb, tab)
    _SHEET_TAB_CACHE[cache_key] = (now, headers, lines)
    return headers, lines


def _pool_from_group(group_val: str) -> str | None:
    """
    Sheet Group column:
      Main  → GCS (otp_accounts)
      Other → Shooter (shooter_accounts)
    """
    g = str(group_val or "").strip().lower()
    if g in ("main", "gcs", "primary"):
        return "gcs"
    if g in ("other", "shooter", "sh", "secondary"):
        return "shooter"
    return None


def _normalize_owner_name(name: str) -> str:
    """Shooter owner from User column (Venus → VENNUS, …)."""
    g = str(name or "").strip()
    if not g:
        return ""
    key = re.sub(r"[^a-z0-9]+", "", g.lower())
    if key in _OWNER_FIX:
        return _OWNER_FIX[key]
    return re.sub(r"[^A-Z0-9]", "", g.upper())


def _slug_user_key(v: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(v or "").strip().lower())


def _resolve_notify_account_from_user(
    raw: dict[str, Any],
    row_user: str,
    matched: dict[str, Any] | None,
) -> str:
    """Map Sheet User column -> accounts[].id (GCS notify_account)."""
    if isinstance(matched, dict):
        keep = str(matched.get("notify_account") or "").strip()
        if keep:
            return keep

    default_notify = str(raw.get("default_account") or "geri_work").strip() or "geri_work"
    user_key = _slug_user_key(row_user)
    if not user_key:
        return default_notify

    for row in raw.get("accounts", []):
        if not isinstance(row, dict):
            continue
        aid = str(row.get("id") or "").strip()
        if not aid:
            continue
        keys = (
            _slug_user_key(str(row.get("id") or "")),
            _slug_user_key(str(row.get("label") or "")),
            _slug_user_key(str(row.get("telegram_username") or "")),
            _slug_user_key(str(row.get("shooter_owner") or "")),
        )
        if user_key in keys:
            return aid
    return default_notify


def _resolve_gcs_api(
    row: dict[str, str],
    raw: dict[str, Any],
    existing: list[dict[str, Any]],
    matched: dict[str, Any] | None,
) -> tuple[str, str]:
    api_id = str(row.get("api_id") or "").strip()
    api_hash = str(row.get("api_hash") or "").strip()
    if api_id and api_hash:
        return api_id, api_hash

    if isinstance(matched, dict):
        mid = str(matched.get("api_id") or "").strip()
        mh = str(matched.get("api_hash") or "").strip()
        if mid and mh:
            return mid, mh

    rid = str(raw.get("api_id") or "").strip()
    rh = str(raw.get("api_hash") or "").strip()
    if rid and rh:
        return rid, rh

    for acc in existing:
        if not isinstance(acc, dict):
            continue
        eid = str(acc.get("api_id") or "").strip()
        eh = str(acc.get("api_hash") or "").strip()
        if eid and eh:
            return eid, eh
    return "", ""


def _credentials_path(root: Path) -> Path:
    raw = os.environ.get("GOOGLE_SHEETS_CREDENTIALS", "").strip()
    if raw:
        p = Path(raw)
        return p if p.is_absolute() else (root / p).resolve()
    for name in ("tg-otp-automation-71a6e40268eb.json", "google-credentials.json"):
        c = root / name
        if c.is_file():
            return c
    return root / "tg-otp-automation-71a6e40268eb.json"


def _sheet_id() -> str:
    return os.environ.get("GOOGLE_SHEET_ID", "").strip()


def _tab_telegram() -> str:
    return os.environ.get("GOOGLE_SHEET_TAB_TELEGRAM", "Telegram Acc").strip() or "Telegram Acc"


def _tab_gcs() -> str:
    return os.environ.get("GOOGLE_SHEET_TAB_GCS", "GCS").strip() or "GCS"


def _tab_shooter() -> str:
    return os.environ.get("GOOGLE_SHEET_TAB_SHOOTER", "Shooter").strip() or "Shooter"


def use_telegram_acc_format() -> bool:
    """True = use Telegram Acc tab (default when GOOGLE_SHEET_ID is set)."""
    v = os.environ.get("GOOGLE_SHEET_USE_TELEGRAM_ACC", "1").strip().lower()
    return v not in ("0", "false", "no", "off")


def status_queue_path(root: Path) -> Path:
    return root / "sheet_status_queue.jsonl"


def instant_push_enabled() -> bool:
    return os.environ.get("TELEGRAM_SYNC_INSTANT_PUSH", "1").strip().lower() not in (
        "0",
        "false",
        "no",
        "off",
    )


def _should_instant_push(session_user: str) -> bool:
    """Push to Sheet immediately for account issues; Active can wait for sync cycle."""
    su = _map_script_status(session_user)
    return su in (
        "Banned",
        "Frozen",
        "Expired",
        "Disconnected",
    )


def classify_account_status(exc: BaseException | None = None, *, message: str = "") -> str:
    """Telegram account status for Sheet Status dropdown (Banned/Frozen/Expired/…)."""
    if exc is not None:
        name = type(exc).__name__.lower()
        msg = str(exc).lower()
    else:
        name = ""
        msg = str(message or "").lower()

    combined = f"{name} {msg}"
    if "phonenumberbanned" in name or "userdeactivatedban" in name or "banned" in combined:
        return "Banned"
    if (
        "frozen_participant" in name
        or "frozen_method_invalid" in name
        or "account is frozen" in combined
        or "your account is frozen" in combined
    ):
        return "Frozen"
    if "peerflood" in name or "userrestricted" in name or "userprivacyrestricted" in name:
        return "Disconnected"
    if "account_banned" in combined or "user_banned" in combined:
        return "Banned"
    if "userdeactivated" in name or "deactivated" in combined:
        return "Banned"
    if "authkeyunregistered" in name or "sessionrevoked" in name or "auth key" in combined:
        return "Expired"
    if "password" in combined and "needed" in combined:
        return "Expired"
    if "expired" in combined or "not authorized" in combined:
        return "Expired"
    if "disconnect" in combined:
        return "Disconnected"
    if "database is locked" in combined or "sqlite" in combined:
        return "Disconnected"
    if message:
        # Avoid "Unknown" in Account Status column.
        return _map_script_status(message) or "Disconnected"
    return "Expired"


def _sheet_status_column_value(raw: str) -> str:
    """
    Status dropdown only — script never writes Pending (staff login trigger).
    Pending Login belongs in Session Friday, not Status.
    """
    su = _map_script_status(raw)
    if su.lower() in ("pending login", "pending"):
        return ""
    return su


def queue_status(
    root: Path,
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
    """
    Queue entry for Sheet push.
    session_user / status → Status column (dropdown). Script never writes Pending.
    session_friday → Session Friday column only.
    allow_instant=False → queue only (LISTEN); LIVE-STATUS bulk-pushes later.
    force_queue=True → always append (e.g. recover false Frozen → Ready/Active).
    """
    su = _sheet_status_column_value(session_user or status)
    sf = _map_script_status(session_friday) if session_friday else ""
    if allow_instant is False and not force_queue:
        su_l = su.lower()
        if su_l in ("active", "feeding", "ready") and (not sf or sf.lower() == "active"):
            return
    if not su and not sf:
        return

    path = status_queue_path(root)
    row = {
        "account_id": account_id,
        "pool": pool,
        "phone": norm_phone(phone),
        "status": status,
        "session_user": su,
        "session_friday": sf,
        "note": note,
        "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    try:
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    except OSError:
        pass

    use_instant = allow_instant if allow_instant is not None else instant_push_enabled()
    if use_instant and row.get("phone") and _should_instant_push(su):
        import threading

        threading.Thread(
            target=_instant_push_worker,
            args=(root, row["phone"], su, sf, account_id, pool),
            daemon=True,
        ).start()


def _instant_push_worker(
    root: Path,
    phone: str,
    session_user: str,
    session_friday: str,
    account_id: str,
    pool: str = "",
) -> None:
    try:
        if push_status_instant(root, phone, session_user, session_friday, pool=pool):
            label = account_id or phone
            friday_part = f" | Friday: {session_friday}" if session_friday else ""
            print(
                f"  📋 Google Sheet updated · {label} → Status: {session_user}{friday_part}",
                flush=True,
            )
    except Exception as e:
        print(f"  ⚠ Google Sheet instant push failed: {e}", file=sys.stderr, flush=True)


def push_status_instant(
    root: Path,
    phone: str,
    session_user: str,
    session_friday: str = "",
    *,
    pool: str = "",
) -> bool:
    """Update Telegram Acc row(s) by phone. pool=gcs|shooter → Main/Other row only."""
    if not _sheet_id() or not use_telegram_acc_format():
        return False
    np = norm_phone(phone)
    if not np:
        return False
    su = _sheet_status_column_value(session_user)
    sf = _map_script_status(session_friday) if session_friday else ""
    pl = str(pool or "").strip().lower()
    if pl in ("gcs", "shooter"):
        by_phone = {_status_map_key(np, pl): {"session_user": su, "session_friday": sf}}
    else:
        by_phone = {np: {"session_user": su, "session_friday": sf}}
    try:
        return _push_telegram_acc(root, by_phone) > 0
    except Exception:
        return False


def _load_gspread():
    import warnings

    warnings.filterwarnings("ignore", category=FutureWarning, module=r"google\.auth")
    warnings.filterwarnings("ignore", category=FutureWarning, module=r"google\.oauth2")
    try:
        from urllib3.exceptions import NotOpenSSLWarning
    except ImportError:
        pass
    else:
        warnings.filterwarnings("ignore", category=NotOpenSSLWarning)
    try:
        import gspread
        from google.oauth2.service_account import Credentials
    except ImportError as e:
        raise RuntimeError(
            "Install: pip install gspread google-auth\n"
            "Then share the Google Sheet with the service account email (Editor)."
        ) from e
    return gspread, Credentials


def open_workbook(root: Path):
    gspread, Credentials = _load_gspread()
    cred_path = _credentials_path(root)
    if not cred_path.is_file():
        raise FileNotFoundError(f"Credentials not found: {cred_path}")
    sid = _sheet_id()
    if not sid:
        raise ValueError("Set GOOGLE_SHEET_ID in .env (ID from the Google Sheet URL).")
    scopes = ["https://www.googleapis.com/auth/spreadsheets"]
    creds = Credentials.from_service_account_file(str(cred_path), scopes=scopes)
    gc = gspread.authorize(creds)
    return gc.open_by_key(sid)


def _extract_login_code(raw: str) -> str:
    """OTP = kolom tidak kosong dan berisi tepat 5 digit (kode login Telegram)."""
    s = str(raw or "").strip()
    if not s:
        return ""
    m = re.search(r"\b(\d{5})\b", s)
    if m:
        return m.group(1)
    digits = re.sub(r"\D", "", s)
    if len(digits) == 5:
        return digits
    return ""


def fetch_phones_by_sheet_status(root: Path, *status_values: str) -> set[str]:
    """
    Phone numbers where column I (Status) matches (default: Pending).
    Empty status_values → use Pending from env / default.
    """
    if not _sheet_id() or not use_telegram_acc_format():
        return set()
    targets = {_normalize_sheet_status_value(s) for s in status_values if str(s).strip()}
    if not targets:
        raw_trigger = os.environ.get("TELEGRAM_SHEET_LOGIN_TRIGGER_STATUS", "Pending").strip()
        targets = {_normalize_sheet_status_value(raw_trigger)}
    try:
        headers, lines = read_telegram_acc_tab(root)
        if not headers:
            return set()
        out: set[str] = set()
        for line in lines:
            if not any(str(c).strip() for c in line):
                continue
            row = _row_dict(headers, line)
            st = _normalize_sheet_status_value(row.get("status", ""))
            if st not in targets:
                continue
            phone = norm_phone(row.get("phone", ""))
            if phone:
                out.add(phone)
        return out
    except Exception:
        return set()


def _sheet_row_hidden_from_bot_list(row: dict[str, str]) -> bool:
    """True when account must not appear in Telegram /main or /other lists."""
    st = _normalize_sheet_status_value(row.get("status", ""))
    sf = _normalize_sheet_status_value(row.get("session_friday", ""))
    pending_login = _normalize_sheet_status_value("Pending Login")
    login_trigger = _normalize_sheet_status_value(
        os.environ.get("TELEGRAM_SHEET_LOGIN_TRIGGER_STATUS", "Pending")
    )
    if st in (pending_login, login_trigger):
        return True
    if sf == pending_login:
        return True
    return False


def fetch_phones_hidden_from_bot_list(root: Path) -> set[str]:
    """
    Phones excluded from bot account lists (/main, /other).
    Pending / Pending Login (Status or Session Friday) — no session ready for staff OTP yet.
    """
    if not _sheet_id() or not use_telegram_acc_format():
        return set()
    try:
        headers, lines = read_telegram_acc_tab(root)
        if not headers:
            return set()
        out: set[str] = set()
        for line in lines:
            if not any(str(c).strip() for c in line):
                continue
            row = _row_dict(headers, line)
            if not _sheet_row_hidden_from_bot_list(row):
                continue
            phone = norm_phone(row.get("phone", ""))
            if phone:
                out.add(phone)
        return out
    except Exception:
        return set()


def fetch_passwords_by_phone(root: Path, *, force: bool = False) -> dict[str, str]:
    """
    Read tab Telegram Acc: phone -> 2FA (header: 2FA / Password / Cloud Password).
    Does not mutate JSON. force=True bypasses read cache (use during login poll).
    """
    if not _sheet_id() or not use_telegram_acc_format():
        return {}
    try:
        headers, lines = read_telegram_acc_tab(root, force=force)
        if not headers:
            return {}
        out: dict[str, str] = {}
        for line in lines:
            if not any(str(c).strip() for c in line):
                continue
            row = _row_dict(headers, line)
            phone = norm_phone(row.get("phone", ""))
            pw = str(row.get("password") or "").strip()
            if phone and pw:
                out[phone] = pw
        return out
    except Exception:
        return {}


def fetch_login_codes_by_phone(root: Path, *, force: bool = False) -> dict[str, str]:
    """
    Read tab Telegram Acc: phone -> OTP (header: OTP / Login Code).
    Accepts cell with exactly 5 digits. force=True bypasses read cache (login poll).
    """
    if not _sheet_id() or not use_telegram_acc_format():
        return {}
    try:
        headers, lines = read_telegram_acc_tab(root, force=force)
        if not headers:
            return {}
        out: dict[str, str] = {}
        for line in lines:
            if not any(str(c).strip() for c in line):
                continue
            row = _row_dict(headers, line)
            phone = norm_phone(row.get("phone", ""))
            code = _extract_login_code(row.get("login_code", ""))
            if phone and code:
                out[phone] = code
        return out
    except Exception:
        return {}


def _update_sheet_cell_by_phone(
    root: Path,
    phone: str,
    column_key: str,
    value: str,
) -> bool:
    """Update satu sel di tab Telegram Acc (by phone). column_key = alias canonical (_HEADER_ALIASES)."""
    np = norm_phone(phone)
    if not np or not _sheet_id() or not use_telegram_acc_format():
        return False
    try:
        wb = open_workbook(root)
        headers, lines = _read_tab_raw(wb, _tab_telegram())
        col = _col_index(headers, column_key)
        phone_col = _col_index(headers, "phone")
        if col is None or phone_col is None:
            return False
        ws = wb.worksheet(_tab_telegram())
        for r_idx, line in enumerate(lines, start=2):
            if phone_col >= len(line):
                continue
            if norm_phone(str(line[phone_col])) != np:
                continue
            cell = f"{_col_to_a1(col + 1)}{r_idx}"
            _batch_update_with_retry(ws, [{"range": cell, "values": [[value]]}])
            invalidate_sheet_cache()
            return True
    except Exception:
        return False
    return False


def update_sheet_status_column(root: Path, phone: str, status_value: str) -> bool:
    """Update Status dropdown: Pending → Ready after successful login."""
    return _update_sheet_cell_by_phone(root, phone, "status", status_value)


def clear_login_code_in_sheet(root: Path, phone: str) -> bool:
    """Clear OTP column after successful login."""
    return _update_sheet_cell_by_phone(root, phone, "login_code", "")


def _read_tab_raw(wb, tab_name: str) -> tuple[list[str], list[list[str]]]:
    try:
        ws = wb.worksheet(tab_name)
    except Exception:
        return [], []
    retries = int(os.environ.get("GOOGLE_SHEET_READ_RETRIES", "4"))
    base_sleep = float(os.environ.get("GOOGLE_SHEET_BATCH_BASE_SLEEP_SEC", "1.0"))
    last_err: Exception | None = None
    for attempt in range(max(1, retries)):
        try:
            values = ws.get_all_values()
            if len(values) < 1:
                return [], []
            return values[0], values[1:]
        except Exception as e:
            last_err = e
            msg = str(e).lower()
            if "429" in msg or "quota" in msg:
                sleep_s = base_sleep * (2**attempt)
                print(
                    f"  ⚠ Sheet read quota (429), retry in {sleep_s:.0f}s...",
                    flush=True,
                )
                time.sleep(sleep_s)
                continue
            raise
    if last_err:
        raise last_err
    return [], []


def _read_tab_rows(wb, tab_name: str, *, require_id: bool = True) -> list[dict[str, str]]:
    headers, lines = _read_tab_raw(wb, tab_name)
    if not headers:
        return []
    rows: list[dict[str, str]] = []
    for line in lines:
        if not any(str(c).strip() for c in line):
            continue
        row = _row_dict(headers, line)
        if require_id and not row.get("id"):
            if not row.get("phone"):
                continue
        rows.append(row)
    return rows


def _upsert_list(rows: list[dict[str, Any]], new_row: dict[str, Any], key: str = "id") -> bool:
    nid = str(new_row.get(key) or "").strip()
    if not nid:
        return False
    for i, r in enumerate(rows):
        if str(r.get(key) or "").strip() == nid:
            merged = dict(r)
            merged.update(new_row)
            rows[i] = merged
            return True
    rows.append(new_row)
    return True


def _find_by_phone(rows: list[dict[str, Any]], phone: str) -> dict[str, Any] | None:
    np = norm_phone(phone)
    if not np:
        return None
    for r in rows:
        if not isinstance(r, dict):
            continue
        if norm_phone(str(r.get("phone") or "")) == np:
            return r
    return None


def _session_user_disabled(st: str) -> bool:
    s = str(st or "").strip().lower()
    return s in ("banned", "frozen", "freeze", "disabled", "inactive", "deleted")


def _gcs_id_needs_fix(aid: str, brand: str) -> bool:
    """True when id was created without Device ID (GERI, GCS_3926, BOSS_JO, …)."""
    a = str(aid or "").strip().upper()
    b = str(brand or "").strip().upper()
    if not a or not b:
        return False
    if a == b or a.startswith(f"{b}_"):
        return False
    if a.startswith("GCS_"):
        return True
    if "_" not in a:
        return True
    return a.split("_", 1)[0] != b


def _new_gcs_id(
    phone: str,
    acc_name: str,
    existing: list[dict[str, Any]],
    *,
    brand_hint: str = "",
    user_name: str = "",
) -> str:
    suffix = re.sub(r"\D", "", phone)[-4:] or "0000"
    brand = str(brand_hint or "").strip().upper()
    user_slug = re.sub(r"[^A-Za-z0-9]+", "_", str(user_name or "").strip()).strip("_").upper()

    if brand and user_slug and not user_slug.replace("_", "").isdigit():
        base = f"{brand}_{user_slug}"[:28]
    elif brand:
        base = f"{brand}_{suffix}"
    else:
        base = f"GCS_{suffix}"

    ids = {str(r.get("id") or "") for r in existing if isinstance(r, dict)}
    if base not in ids:
        return base
    n = 2
    while f"{base}_{n}" in ids:
        n += 1
    return f"{base}_{n}"


def shooter_rename_on_owner_change() -> bool:
    """Full pull: rename SH_OLD_* → SH_NEW_* when Sheet User/owner changes."""
    v = os.environ.get("TELEGRAM_SYNC_SHOOTER_RENAME_ON_OWNER", "1").strip().lower()
    return v not in ("0", "false", "no", "off")


def _shooter_id_numeric_suffix(old_id: str, phone: str) -> str:
    """Keep _01 / _02 from existing id; fallback to last 4 digits of phone."""
    m = re.match(r"^SH_[A-Z0-9]+_(.+)$", str(old_id or "").strip(), re.I)
    if m:
        return str(m.group(1)).strip().upper()
    return re.sub(r"\D", "", phone)[-4:] or "0000"


def _canonical_shooter_id(owner: str, suffix: str) -> str:
    owner_u = _normalize_owner_name(owner) or str(owner or "").strip().upper() or "UNKNOWN"
    suf = str(suffix or "").strip().upper() or "0000"
    return f"SH_{owner_u}_{suf}"


def _resolve_shooter_id_with_suffix(
    owner: str,
    suffix: str,
    existing: list[dict[str, Any]],
    *,
    current_id: str = "",
    phone: str = "",
) -> str:
    canonical = _canonical_shooter_id(owner, suffix)
    if not canonical:
        return _new_shooter_id(owner, phone, existing)
    for r in existing:
        if not isinstance(r, dict):
            continue
        rid = str(r.get("id") or "").strip()
        if rid != canonical:
            continue
        if current_id and rid == current_id:
            return canonical
        if current_id and rid != current_id:
            return _new_shooter_id(owner, phone, existing)
        return canonical
    return canonical


def _new_shooter_id(owner: str, phone: str, existing: list[dict[str, Any]]) -> str:
    suffix = re.sub(r"\D", "", phone)[-4:] or "0000"
    base = _canonical_shooter_id(owner, suffix)
    ids = {str(r.get("id") or "") for r in existing if isinstance(r, dict)}
    if base not in ids:
        return base
    n = 2
    while f"{base}_{n}" in ids:
        n += 1
    return f"{base}_{n}"


def _migrate_shooter_session_files(root: Path, old_id: str, new_id: str) -> int:
    """Move Telethon session files when shooter account id changes. Returns files moved."""
    if not old_id or not new_id or old_id == new_id:
        return 0
    shooter_dir = root / "telegram_session" / "shooter"
    moved = 0
    for name in (f"{old_id}.session", f"{old_id}.session-journal"):
        src = shooter_dir / name
        if not src.is_file():
            continue
        dst_name = name.replace(old_id, new_id, 1)
        dst = shooter_dir / dst_name
        if dst.is_file():
            continue
        try:
            src.rename(dst)
            moved += 1
        except OSError:
            pass
    return moved


def _reconcile_shooter_session_files(
    root: Path, accounts: list[dict[str, Any]]
) -> tuple[int, list[tuple[str, str]]]:
    """
    Safety net: JSON id already updated (e.g. owner rename) but .session still under SH_OLD_*.
    Match by account id suffix and rename to current account id.
    Returns (count migrated, list of (old_id, new_id) pairs).
    """
    if not shooter_rename_on_owner_change():
        return 0, []
    shooter_dir = root / "telegram_session" / "shooter"
    if not shooter_dir.is_dir():
        return 0, []
    reconciled = 0
    migrated_pairs: list[tuple[str, str]] = []
    for acc in accounts:
        if not isinstance(acc, dict):
            continue
        new_id = str(acc.get("id") or "").strip()
        phone = str(acc.get("phone") or "")
        if not new_id.upper().startswith("SH_"):
            continue
        suffix = _shooter_id_numeric_suffix(new_id, phone)
        expected = shooter_dir / f"{new_id}.session"
        if expected.is_file() and expected.stat().st_size >= 1024:
            continue
        for src in sorted(shooter_dir.glob(f"SH_*_{suffix}.session")):
            old_id = src.stem
            if old_id.upper() == new_id.upper():
                continue
            if _migrate_shooter_session_files(root, old_id, new_id):
                reconciled += 1
                migrated_pairs.append((old_id, new_id))
                break
    return reconciled, migrated_pairs


def _cleanup_migrated_shooter_sessions(
    root: Path, migrated_pairs: list[tuple[str, str]]
) -> int:
    """Remove source session files only after a successful rename in the same pull."""
    if not migrated_pairs:
        return 0
    shooter_dir = root / "telegram_session" / "shooter"
    removed = 0
    for old_id, new_id in migrated_pairs:
        if not old_id or old_id == new_id:
            continue
        expected = shooter_dir / f"{new_id}.session"
        if not expected.is_file():
            continue
        for name in (f"{old_id}.session", f"{old_id}.session-journal"):
            src = shooter_dir / name
            if not src.is_file():
                continue
            try:
                src.unlink()
                removed += 1
            except OSError:
                pass
    return removed


def _should_skip_wealth_gcs_row(row: dict[str, str]) -> bool:
    """Baris wealth (W+ plus) — bukan GCS brand, jangan masuk otp_accounts."""
    user = str(row.get("user") or "").strip().lower()
    dev = str(row.get("device_id") or "").strip().lower()
    return dev == "wealth" or ("w+" in user and "plus" in user)


_MYR_DEVICE_HEAD = re.compile(r"^MYR-(SB|JM|ST)\b", re.I)
_EXCLUDED_GCS_ID = re.compile(r"^(GCS_\w+|SBMY_\d{4}|JMMY_\d{4})$", re.I)


def _should_skip_gcs_row(row: dict[str, str]) -> bool:
    """Skip wealth + baris MYR-SB/JM test (bukan akun GCS asli). STMY (MYR-ST) tetap."""
    if _should_skip_wealth_gcs_row(row):
        return True
    dev = str(row.get("device_id") or "").strip()
    head = dev.split()[0] if dev else ""
    m = _MYR_DEVICE_HEAD.match(head)
    if not m:
        return False
    code = m.group(1).upper()
    if code == "ST":
        return False
    brand = "SBMY" if code == "SB" else "JMMY" if code == "JM" else ""
    if not brand:
        return False
    acc = str(row.get("acc_name") or row.get("profile_hint") or "").strip().upper()
    return brand not in acc


def _is_excluded_otp_account(row: dict[str, Any]) -> bool:
    aid = str(row.get("id") or "").strip()
    if _EXCLUDED_GCS_ID.match(aid):
        return True
    if str(row.get("device_id") or "").strip().lower() == "wealth":
        return True
    return False


def _prune_excluded_gcs_accounts(lst: list[dict[str, Any]]) -> int:
    before = len(lst)
    lst[:] = [r for r in lst if isinstance(r, dict) and not _is_excluded_otp_account(r)]
    return before - len(lst)


def _telegram_row_to_gcs(
    row: dict[str, str], raw: dict[str, Any], existing: list[dict[str, Any]]
) -> dict[str, Any] | None:
    """Baris Group=Main → otp_accounts (GCS)."""
    if _pool_from_group(row.get("group", "")) != "gcs":
        return None
    phone = norm_phone(row.get("phone", ""))
    if not phone:
        return None
    matched = _find_by_phone(existing, phone)
    if _should_skip_gcs_row(row):
        return None

    api_id, api_hash = _resolve_gcs_api(row, raw, existing, matched)
    if not api_id or not api_hash:
        return None

    acc_name = row.get("acc_name") or row.get("profile_hint") or ""
    account_status = effective_row_status(row)
    device_id_raw = str(row.get("device_id") or "").strip()
    brands_cfg = {
        str(k).strip().upper(): v
        for k, v in (raw.get("brands") or {}).items()
        if isinstance(v, dict)
    }
    row_user = str(row.get("user") or "").strip()

    aid = str(matched.get("id") if matched else "").strip()
    if not matched:
        brand_hint = infer_gcs_brand(
            device_id=device_id_raw,
            acc_name=acc_name,
            brands_cfg=brands_cfg,
        ) or ""
        aid = _new_gcs_id(
            phone,
            acc_name,
            existing,
            brand_hint=brand_hint,
            user_name=row_user,
        )

    enabled = _truthy(row.get("enabled", "1"))
    if _session_user_disabled(account_status):
        enabled = False

    session_default = f"telegram_session/{aid}"
    old_session = str(matched.get("session") or "") if matched else ""
    if matched and aid != str(matched.get("id") or ""):
        session_path = session_default
    else:
        session_path = old_session or session_default

    out: dict[str, Any] = {
        "id": aid,
        "phone": phone,
        "api_id": int(api_id),
        "api_hash": api_hash,
        "enabled": enabled,
        "session": session_path,
        "notify_account": _resolve_notify_account_from_user(raw, row.get("user", ""), matched),
    }
    if row_user:
        out["user_name"] = row_user
    elif matched and str(matched.get("user_name") or "").strip():
        out["user_name"] = str(matched.get("user_name") or "").strip()
    if acc_name:
        out["profile_hint"] = acc_name
    if row.get("password"):
        out["password"] = row["password"]
    if device_id_raw:
        out["device_id"] = device_id_raw
    if matched:
        prev_b = str(matched.get("brand") or "").strip().upper()
        if prev_b and not is_currency_code(prev_b):
            out["brand"] = prev_b
        else:
            resolved = resolve_brand_from_id(aid, brands_cfg)
            if resolved:
                out["brand"] = resolved
    else:
        inferred = infer_gcs_brand(
            device_id=device_id_raw,
            acc_name=acc_name,
            account_id=aid,
            brand=str(row.get("brand") or ""),
            brands_cfg=brands_cfg,
        )
        if inferred:
            out["brand"] = inferred
    return out


def _telegram_row_to_shooter(row: dict[str, str], raw: dict[str, Any], existing: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Baris Group=Other → shooter_accounts."""
    if _pool_from_group(row.get("group", "")) != "shooter":
        return None
    phone = norm_phone(row.get("phone", ""))
    if not phone:
        return None
    owner = _normalize_owner_name(row.get("user") or row.get("owner") or "")
    acc_name = row.get("acc_name") or row.get("profile_hint") or ""
    account_status = effective_row_status(row)

    matched = _find_by_phone(existing, phone)
    old_id = str(matched.get("id") if matched else "").strip()
    final_owner = owner or _normalize_owner_name(str(matched.get("owner") or "") if matched else "")
    aid = old_id
    if not aid:
        if not final_owner:
            return None
        aid = _new_shooter_id(final_owner, phone, existing)
    elif (
        matched
        and shooter_rename_on_owner_change()
        and final_owner
        and final_owner != _normalize_owner_name(str(matched.get("owner") or ""))
    ):
        suffix = _shooter_id_numeric_suffix(old_id, phone)
        aid = _resolve_shooter_id_with_suffix(
            final_owner,
            suffix,
            existing,
            current_id=old_id,
            phone=phone,
        )

    enabled = _truthy(row.get("enabled", "1"))
    if _session_user_disabled(account_status):
        enabled = False

    session_default = f"telegram_session/shooter/{aid}"
    session_val = session_default
    if matched and aid == old_id:
        session_val = str(matched.get("session") or "").strip() or session_default
    out: dict[str, Any] = {
        "id": aid,
        "phone": phone,
        "owner": final_owner or (str(matched.get("owner") if matched else "") or "UNKNOWN"),
        "enabled": enabled,
        "session": session_val,
    }
    row_user = str(row.get("user") or row.get("owner") or "").strip()
    if row_user:
        out["user_name"] = row_user
    elif matched and str(matched.get("user_name") or "").strip():
        out["user_name"] = str(matched.get("user_name") or "").strip()
    if acc_name:
        out["profile_hint"] = acc_name
    if row.get("password"):
        out["password"] = row["password"]
    device_id_raw = str(row.get("device_id") or "").strip()
    if device_id_raw:
        out["remark"] = device_id_raw
        brands_cfg = {
            str(k).strip().upper(): v
            for k, v in (raw.get("brands") or {}).items()
            if isinstance(v, dict)
        }
        currency, _code = parse_device_id(device_id_raw)
        brand_from_dev = infer_gcs_brand(
            device_id=device_id_raw,
            acc_name=acc_name,
            brands_cfg=brands_cfg,
        )
        if brand_from_dev:
            out["brand"] = brand_from_dev
        if currency:
            out["currency"] = currency
    return out


def _sheet_phone_pool_sets(
    headers: list[str], lines: list[list[Any]]
) -> tuple[set[str], set[str]]:
    """
    Phones in Sheet tab Telegram Acc by Group column.
    Main → GCS (accounts.json). Other → Shooter (shooteraccounts.json).
    Same phone in both groups is allowed (appears in /main and /other).
    """
    main_phones: set[str] = set()
    other_phones: set[str] = set()
    for line in lines:
        if not any(str(c).strip() for c in line):
            continue
        row = _row_dict(headers, line)
        phone = norm_phone(row.get("phone", ""))
        if not phone:
            continue
        pool = _pool_from_group(row.get("group", ""))
        if pool == "gcs":
            main_phones.add(phone)
        elif pool == "shooter":
            other_phones.add(phone)
    return main_phones, other_phones


def _prune_json_pool_mismatch(
    lst: list[dict[str, Any]],
    *,
    main_phones: set[str],
    other_phones: set[str],
    keep_pool: str,
) -> int:
    """
    Remove rows whose phone is in Sheet under the opposite pool only.
    keep_pool: 'gcs' | 'shooter'
    Phones absent from Sheet are kept (legacy / manual JSON).
    """
    other_only = other_phones - main_phones
    main_only = main_phones - other_phones
    in_sheet = main_phones | other_phones
    remove_if: set[str]
    if keep_pool == "gcs":
        remove_if = other_only
    else:
        remove_if = main_only
    before = len(lst)
    lst[:] = [
        r
        for r in lst
        if isinstance(r, dict)
        and (
            norm_phone(str(r.get("phone") or "")) not in in_sheet
            or norm_phone(str(r.get("phone") or "")) not in remove_if
        )
    ]
    return before - len(lst)


def _migrate_gcs_session_to_shooter(
    root: Path,
    shooter_acc: dict[str, Any],
    gcs_snapshot: dict[str, dict[str, Any]],
) -> int:
    """
    When Sheet Group moves phone GCS → Shooter, copy existing GCS .session to shooter path.
    Does not delete the GCS session file (Main row may still need it).
    """
    import shutil

    phone = norm_phone(str(shooter_acc.get("phone") or ""))
    shooter_id = str(shooter_acc.get("id") or "").strip()
    if not phone or not shooter_id:
        return 0
    dst = root / "telegram_session" / "shooter" / f"{shooter_id}.session"
    if dst.is_file() and dst.stat().st_size >= 1024:
        return 0
    old = gcs_snapshot.get(phone)
    if not old:
        return 0
    gid = str(old.get("id") or "").strip()
    if not gid:
        return 0
    src = root / "telegram_session" / f"{gid}.session"
    if not src.is_file() or src.stat().st_size < 1024:
        return 0
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    for ext in ("-journal",):
        sj = Path(str(src) + ext)
        if sj.is_file():
            shutil.copy2(sj, Path(str(dst) + ext))
    return 1


def _pull_telegram_acc(
    wb,
    mutate_accounts: Callable[[dict[str, Any]], bool],
    mutate_shooter: Callable[[dict[str, Any]], bool],
    *,
    root: Path | None = None,
    headers_lines: tuple[list[str], list[list[str]]] | None = None,
    pending_only: bool = False,
) -> dict[str, int]:
    if headers_lines:
        headers, lines = headers_lines
    else:
        headers, lines = _read_tab_raw(wb, _tab_telegram())
    stats = {
        "shooter_added": 0, "shooter_updated": 0, "shooter_skipped": 0,
        "shooter_renamed": 0, "shooter_session_migrated": 0, "shooter_session_cleaned": 0,
        "gcs_added": 0, "gcs_updated": 0, "gcs_skipped": 0,
        "gcs_pruned_other_pool": 0, "shooter_pruned_main_pool": 0,
        "gcs_session_to_shooter": 0,
    }
    main_phones, other_phones = _sheet_phone_pool_sets(headers, lines)
    gcs_snapshot_before_pull: dict[str, dict[str, Any]] = {}
    shooter_phone_map: dict[str, dict[str, Any]] = {}
    if root:
        try:
            import json as _json

            sh_path = root / "shooteraccounts.json"
            if sh_path.is_file():
                sh_raw = _json.loads(sh_path.read_text(encoding="utf-8"))
                for row in sh_raw.get("shooter_accounts") or []:
                    if not isinstance(row, dict):
                        continue
                    p = norm_phone(str(row.get("phone") or ""))
                    if p:
                        shooter_phone_map[p] = row
        except (OSError, ValueError):
            pass

    def _apply_gcs(data: dict[str, Any]) -> None:
        nonlocal stats, gcs_snapshot_before_pull
        lst = data.setdefault("otp_accounts", [])
        if not isinstance(lst, list):
            lst = []
            data["otp_accounts"] = lst
        gcs_snapshot_before_pull = {
            norm_phone(str(r.get("phone") or "")): dict(r)
            for r in lst
            if isinstance(r, dict) and str(r.get("phone") or "").strip()
        }
        for line in lines:
            if not any(str(c).strip() for c in line):
                continue
            row = _row_dict(headers, line)
            if pending_only:
                if _pool_from_group(row.get("group", "")) != "gcs":
                    continue
                np = norm_phone(row.get("phone", ""))
                if not np:
                    stats["gcs_skipped"] += 1
                    continue
                if not _find_by_phone(lst, np):
                    if not sheet_status_is_login_trigger(effective_row_status(row)):
                        stats["gcs_skipped"] += 1
                        continue
            entry = _telegram_row_to_gcs(row, data, lst)
            if not entry:
                if _pool_from_group(row.get("group", "")) == "gcs":
                    stats["gcs_skipped"] += 1
                continue
            phone = entry["phone"]
            matched = _find_by_phone(lst, phone)
            if matched:
                entry["id"] = str(matched.get("id") or entry.get("id") or "").strip()
                if matched.get("session"):
                    entry["session"] = matched["session"]
                for i, r in enumerate(lst):
                    if norm_phone(str(r.get("phone") or "")) == norm_phone(phone):
                        merged = dict(r)
                        merged.update(entry)
                        merged["id"] = entry["id"]
                        lst[i] = merged
                        break
                stats["gcs_updated"] += 1
            else:
                _upsert_list(lst, entry, key="id")
                stats["gcs_added"] += 1
        pruned = _prune_excluded_gcs_accounts(lst)
        if pruned:
            stats["gcs_skipped"] += pruned
        other_only = other_phones - main_phones
        if root and other_only:
            for row in list(lst):
                if not isinstance(row, dict):
                    continue
                phone = norm_phone(str(row.get("phone") or ""))
                if phone not in other_only:
                    continue
                sh_acc = shooter_phone_map.get(phone)
                if sh_acc:
                    stats["gcs_session_to_shooter"] += _migrate_gcs_session_to_shooter(
                        root, sh_acc, {phone: row}
                    )
        stats["gcs_pruned_other_pool"] += _prune_json_pool_mismatch(
            lst,
            main_phones=main_phones,
            other_phones=other_phones,
            keep_pool="gcs",
        )

    def _apply_shooter(data: dict[str, Any]) -> None:
        nonlocal stats
        lst = data.setdefault("shooter_accounts", [])
        if not isinstance(lst, list):
            lst = []
            data["shooter_accounts"] = lst
        for line in lines:
            if not any(str(c).strip() for c in line):
                continue
            row = _row_dict(headers, line)
            if pending_only:
                if _pool_from_group(row.get("group", "")) != "shooter":
                    continue
                np = norm_phone(row.get("phone", ""))
                if not np:
                    stats["shooter_skipped"] += 1
                    continue
                if not _find_by_phone(lst, np):
                    if not sheet_status_is_login_trigger(effective_row_status(row)):
                        stats["shooter_skipped"] += 1
                        continue
            entry = _telegram_row_to_shooter(row, data, lst)
            if not entry:
                if _pool_from_group(row.get("group", "")) == "shooter":
                    stats["shooter_skipped"] += 1
                continue
            phone = entry["phone"]
            matched = _find_by_phone(lst, phone)
            before = matched is not None
            old_id = str(matched.get("id") or "").strip() if matched else ""
            new_id = str(entry.get("id") or "").strip()
            if root and old_id and new_id and old_id != new_id:
                _migrate_shooter_session_files(root, old_id, new_id)
                stats["shooter_renamed"] += 1
            if matched:
                for i, r in enumerate(lst):
                    if not isinstance(r, dict):
                        continue
                    if norm_phone(str(r.get("phone") or "")) != norm_phone(phone):
                        continue
                    merged = dict(r)
                    merged.update(entry)
                    merged["id"] = new_id
                    merged["session"] = f"telegram_session/shooter/{new_id}"
                    lst[i] = merged
                    break
                if old_id and new_id != old_id:
                    lst[:] = [
                        r
                        for r in lst
                        if not (
                            isinstance(r, dict) and str(r.get("id") or "").strip() == old_id
                        )
                    ]
                stats["shooter_updated"] += 1
            else:
                _upsert_list(lst, entry, key="id")
                stats["shooter_added"] += 1
        if root:
            migrated_n, migrated_pairs = _reconcile_shooter_session_files(root, lst)
            stats["shooter_session_migrated"] += migrated_n
            stats["shooter_session_cleaned"] += _cleanup_migrated_shooter_sessions(
                root, migrated_pairs
            )
            for acc in lst:
                if isinstance(acc, dict):
                    stats["gcs_session_to_shooter"] += _migrate_gcs_session_to_shooter(
                        root, acc, gcs_snapshot_before_pull
                    )
        stats["shooter_pruned_main_pool"] += _prune_json_pool_mismatch(
            lst,
            main_phones=main_phones,
            other_phones=other_phones,
            keep_pool="shooter",
        )

    if not mutate_accounts(_apply_gcs):
        raise RuntimeError("Failed to write accounts.json (lock timeout?)")
    if not mutate_shooter(_apply_shooter):
        raise RuntimeError("Failed to write shooteraccounts.json (lock timeout?)")
    return stats


def _sheet_row_to_gcs(row: dict[str, str], raw: dict[str, Any], root: Path) -> dict[str, Any] | None:
    aid = row.get("id", "").strip()
    phone = norm_phone(row.get("phone", ""))
    if not aid or not phone:
        return None
    api_id = row.get("api_id") or str(raw.get("api_id") or "")
    api_hash = row.get("api_hash") or str(raw.get("api_hash") or "")
    if not api_id or not api_hash:
        return None
    session_default = f"telegram_session/{aid}"
    st = effective_row_status(row)
    enabled = _truthy(row.get("enabled", "1")) and not _session_user_disabled(st)
    out: dict[str, Any] = {
        "id": aid,
        "phone": phone,
        "api_id": int(api_id),
        "api_hash": api_hash,
        "enabled": enabled,
        "session": row.get("session") or session_default,
    }
    if row.get("profile_hint") or row.get("acc_name"):
        out["profile_hint"] = row.get("profile_hint") or row.get("acc_name")
    if row.get("password"):
        out["password"] = row["password"]
    if row.get("brand"):
        out["brand"] = row["brand"]
    return out


def _sheet_row_to_shooter_legacy(row: dict[str, str], raw: dict[str, Any]) -> dict[str, Any] | None:
    aid = row.get("id", "").strip()
    phone = norm_phone(row.get("phone", ""))
    owner = (row.get("owner") or row.get("group") or "").strip().upper()
    if not aid or not phone or not owner:
        return None
    st = effective_row_status(row)
    enabled = _truthy(row.get("enabled", "1")) and not _session_user_disabled(st)
    return {
        "id": aid,
        "phone": phone,
        "owner": owner,
        "enabled": enabled,
        "session": row.get("session") or f"telegram_session/shooter/{aid}",
        "profile_hint": row.get("profile_hint") or row.get("acc_name") or None,
    }


def pull_from_sheet(
    root: Path,
    mutate_accounts: Callable[[dict[str, Any]], bool],
    mutate_shooter: Callable[[dict[str, Any]], bool],
    *,
    pending_only: bool | None = None,
) -> dict[str, int]:
    if pending_only is None:
        pending_only = pull_register_pending_only()
    wb = open_workbook(root)
    if use_telegram_acc_format():
        headers, lines = _read_tab_raw(wb, _tab_telegram())
        tab = _tab_telegram()
        _SHEET_TAB_CACHE[f"{_sheet_id()}:{tab}"] = (time.time(), headers, lines)
        return _pull_telegram_acc(
            wb,
            mutate_accounts,
            mutate_shooter,
            root=root,
            headers_lines=(headers, lines),
            pending_only=pending_only,
        )

    gcs_rows = _read_tab_rows(wb, _tab_gcs())
    sh_rows = _read_tab_rows(wb, _tab_shooter())
    stats = {
        "gcs_added": 0, "gcs_updated": 0, "shooter_added": 0, "shooter_updated": 0,
        "gcs_skipped": 0, "shooter_skipped": 0,
    }

    def _apply_gcs(data: dict[str, Any]) -> None:
        nonlocal stats
        lst = data.setdefault("otp_accounts", [])
        if not isinstance(lst, list):
            lst = []
            data["otp_accounts"] = lst
        existing_ids = {str(r.get("id") or "") for r in lst if isinstance(r, dict)}
        for row in gcs_rows:
            entry = _sheet_row_to_gcs(row, data, root)
            if not entry:
                stats["gcs_skipped"] += 1
                continue
            aid = entry["id"]
            before = aid in existing_ids
            _upsert_list(lst, entry)
            stats["gcs_updated" if before else "gcs_added"] += 1
            if not before:
                existing_ids.add(aid)

    def _apply_shooter(data: dict[str, Any]) -> None:
        nonlocal stats
        lst = data.setdefault("shooter_accounts", [])
        if not isinstance(lst, list):
            lst = []
            data["shooter_accounts"] = lst
        existing_ids = {str(r.get("id") or "") for r in lst if isinstance(r, dict)}
        for row in sh_rows:
            entry = _sheet_row_to_shooter_legacy(row, data)
            if not entry:
                stats["shooter_skipped"] += 1
                continue
            aid = entry["id"]
            before = aid in existing_ids
            _upsert_list(lst, entry)
            stats["shooter_updated" if before else "shooter_added"] += 1
            if not before:
                existing_ids.add(aid)

    if not mutate_accounts(_apply_gcs):
        raise RuntimeError("Failed to write accounts.json (lock timeout?)")
    if not mutate_shooter(_apply_shooter):
        raise RuntimeError("Failed to write shooteraccounts.json (lock timeout?)")
    return stats


def _session_status(session_path: Path) -> str:
    sf = (
        Path(str(session_path) + ".session")
        if not str(session_path).endswith(".session")
        else session_path
    )
    if sf.is_file() and sf.stat().st_size >= 1024:
        return "Active"
    return "Pending Login"


def _normalize_sheet_display(st: str) -> str:
    return _map_script_status(str(st or "").strip()) or str(st or "").strip()


def _map_script_status(st: str) -> str:
    s = str(st or "").strip().lower()
    mapping = {
        "active": "Active",
        "pending": "Pending",
        "ready": "Ready",
        "feeding": "Feeding",
        "ready": "Ready",
        "pending_login": "Pending Login",
        "expired": "Expired",
        "disconnected": "Disconnected",
        "banned": "Banned",
        "frozen": "Frozen",
        "freeze": "Frozen",
    }
    return mapping.get(s, st.title() if st else "")


def _skip_sheet_status_write(old: str, new: str) -> bool:
    """True = no Sheet write needed (unchanged or redundant)."""
    o = _normalize_sheet_display(old).lower()
    n = _normalize_sheet_display(new).lower()
    if not n:
        return True
    if o == n:
        return True
    if o == "active" and n == "active":
        return True
    if o == "feeding" and n in ("active", "feeding", "ready"):
        return True
    if o == "ready" and n in ("active", "ready", "feeding"):
        return True
    return False


def _sheet_status_locked(raw: str) -> bool:
    """Staff-set terminal states — script must not overwrite with Ready/Active."""
    return _normalize_sheet_display(raw).lower() in ("frozen", "banned", "expired")


def _script_may_write_status(old: str, new: str) -> bool:
    """
    Protect Status dropdown: staff Pending is login trigger — script must not overwrite
    with Active/Ready until LIVE-LOGIN completes (except Banned/Frozen/Expired).
    Frozen/Banned/Expired on Sheet are never overwritten by script.
    """
    if _skip_sheet_status_write(old, new):
        return False
    if _sheet_status_locked(old):
        return False
    if sheet_status_is_login_trigger(old):
        new_n = _normalize_sheet_status_value(_map_script_status(new))
        after = _normalize_sheet_status_value(sheet_status_after_login_value())
        if new_n in (
            after,
            "banned",
            "frozen",
            "expired",
            "disconnected",
        ):
            return True
        return False
    return True


def _status_map_key(phone: str, pool: str) -> str:
    p = norm_phone(phone)
    pl = str(pool or "gcs").strip().lower()
    if pl not in ("gcs", "shooter"):
        pl = "gcs"
    return f"{p}|{pl}"


def _lookup_status_info(
    by_phone: dict[str, dict[str, str]], phone: str, pool: str | None
) -> dict[str, str] | None:
    if not phone:
        return None
    pl = _pool_from_group(str(pool or "")) if pool else None
    if pl:
        hit = by_phone.get(_status_map_key(phone, pl))
        if hit:
            return hit
    return by_phone.get(norm_phone(phone))


def _derive_status_from_session(
    session_friday: str,
    session_user: str = "",
) -> str:
    """Status column: Ready when Session Friday is Active (session file exists)."""
    su = _sheet_status_column_value(session_user)
    if su and _sheet_status_locked(su):
        return su
    sf = _normalize_sheet_display(session_friday).lower()
    if sf == "active":
        return sheet_status_after_login_value()
    if su:
        return su
    if sf in ("banned", "frozen", "expired", "disconnected"):
        return _map_script_status(session_friday)
    return ""


def collect_status_by_phone(
    root: Path,
    gcs_accounts: list[dict[str, Any]],
    shooter_accounts: list[dict[str, Any]],
) -> dict[str, dict[str, str]]:
    """
    phone|pool → {session_user, session_friday, …}
    Main (GCS) and Other (Shooter) rows with the same phone can differ.

    Account Status = account state (Active / Banned / Frozen / Expired / …)
    Session Friday = FRIDAY_BO bot session only (Active / Disconnected / Pending Login)
    """
    out: dict[str, dict[str, str]] = {}
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")

    def _add(acc: dict[str, Any], pool: str) -> None:
        phone = norm_phone(str(acc.get("phone") or ""))
        if not phone:
            return
        # Friday = whether the bot session file exists (owner account may still be inactive).
        friday = _session_status(Path(acc["session"]))
        session_user = _derive_status_from_session(friday)
        out[_status_map_key(phone, pool)] = {
            "session_user": session_user,
            "session_friday": friday,
            "notes": "",
            "at": now,
            "account_id": str(acc.get("id") or ""),
            "pool": pool,
        }

    for acc in gcs_accounts:
        _add(acc, "gcs")
    for acc in shooter_accounts:
        _add(acc, "shooter")

    qpath = status_queue_path(root)
    if qpath.is_file():
        try:
            for line in qpath.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                ev = json.loads(line)
                phone = norm_phone(str(ev.get("phone") or ""))
                aid = str(ev.get("account_id") or "")
                pool = str(ev.get("pool") or "gcs").strip().lower()
                if pool not in ("gcs", "shooter"):
                    pool = "gcs"
                su = _map_script_status(
                    str(ev.get("session_user") or ev.get("status") or "")
                )
                sf = _map_script_status(str(ev.get("session_friday") or ""))
                if not su and not sf:
                    continue
                key_phone = phone
                if not key_phone and aid:
                    for k, info in out.items():
                        if info.get("account_id") == aid:
                            key_phone = k.split("|", 1)[0]
                            pool = k.split("|", 1)[1] if "|" in k else pool
                            break
                if not key_phone:
                    continue
                map_key = _status_map_key(key_phone, pool)
                prev = out.get(map_key, {})
                su = su or prev.get("session_user", "")
                sf = sf or prev.get("session_friday", "")
                su = _derive_status_from_session(sf, su)
                out[map_key] = {
                    "session_user": su,
                    "session_friday": sf,
                    "notes": str(ev.get("note") or prev.get("notes") or ""),
                    "at": str(ev.get("at") or now),
                    "account_id": aid or prev.get("account_id", ""),
                    "pool": pool or prev.get("pool", ""),
                }
        except (OSError, json.JSONDecodeError):
            pass
    return out


def collect_status_from_queue(
    root: Path,
    gcs_accounts: list[dict[str, Any]] | None = None,
    shooter_accounts: list[dict[str, Any]] | None = None,
) -> dict[str, dict[str, str]]:
    """Gabung antrian sheet_status_queue.jsonl — latest per phone, tanpa baseline full scan."""
    qpath = status_queue_path(root)
    if not qpath.is_file():
        return {}

    aid_to_phone: dict[str, str] = {}
    if gcs_accounts is not None and shooter_accounts is not None:
        for acc in gcs_accounts + shooter_accounts:
            phone = norm_phone(str(acc.get("phone") or ""))
            aid = str(acc.get("id") or "")
            if phone and aid:
                aid_to_phone[aid] = phone

    out: dict[str, dict[str, str]] = {}
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
    try:
        for line in qpath.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            ev = json.loads(line)
            phone = norm_phone(str(ev.get("phone") or ""))
            aid = str(ev.get("account_id") or "")
            pool = str(ev.get("pool") or "gcs").strip().lower()
            if pool not in ("gcs", "shooter"):
                pool = "gcs"
            su = _map_script_status(str(ev.get("session_user") or ev.get("status") or ""))
            sf = _map_script_status(str(ev.get("session_friday") or ""))
            if not su and not sf:
                continue
            key_phone = phone or aid_to_phone.get(aid, "")
            if not key_phone:
                continue
            map_key = _status_map_key(key_phone, pool)
            prev = out.get(map_key, {})
            su = su or prev.get("session_user", "")
            sf = sf or prev.get("session_friday", "")
            su = _derive_status_from_session(sf, su)
            out[map_key] = {
                "session_user": su,
                "session_friday": sf,
                "notes": str(ev.get("note") or prev.get("notes") or ""),
                "at": str(ev.get("at") or now),
                "account_id": aid or prev.get("account_id", ""),
                "pool": pool or prev.get("pool", ""),
            }
    except (OSError, json.JSONDecodeError):
        pass
    return out


def compact_status_queue(root: Path, *, max_lines: int | None = None) -> int:
    """
    Keep latest entry per phone; cap total lines.
    Returns number of lines removed.
    """
    qpath = status_queue_path(root)
    if not qpath.is_file():
        return 0
    cap = max_lines
    if cap is None:
        raw = os.environ.get("TELEGRAM_STATUS_QUEUE_MAX_LINES", "2000").strip()
        try:
            cap = max(100, int(raw))
        except ValueError:
            cap = 2000
    try:
        lines = [ln.strip() for ln in qpath.read_text(encoding="utf-8").splitlines() if ln.strip()]
    except OSError:
        return 0
    before = len(lines)
    latest: dict[str, str] = {}
    order: list[str] = []
    for raw in lines:
        try:
            ev = json.loads(raw)
        except json.JSONDecodeError:
            continue
        p = norm_phone(str(ev.get("phone") or ""))
        if not p:
            continue
        if p not in latest:
            order.append(p)
        latest[p] = raw
    kept_order = order[-cap:] if len(order) > cap else order
    kept = [latest[p] for p in kept_order if p in latest]
    try:
        if kept:
            qpath.write_text("\n".join(kept) + "\n", encoding="utf-8")
        else:
            qpath.unlink(missing_ok=True)
    except OSError:
        return 0
    return before - len(kept)


def _trim_status_queue(root: Path, phones: set[str]) -> None:
    """Remove queue entries for phones successfully pushed to Sheet."""
    if not phones:
        return
    qpath = status_queue_path(root)
    if not qpath.is_file():
        return
    kept: list[str] = []
    try:
        for line in qpath.read_text(encoding="utf-8").splitlines():
            raw = line.strip()
            if not raw:
                continue
            try:
                ev = json.loads(raw)
            except json.JSONDecodeError:
                kept.append(raw)
                continue
            p = norm_phone(str(ev.get("phone") or ""))
            if p and p in phones:
                continue
            kept.append(raw)
        if kept:
            qpath.write_text("\n".join(kept) + "\n", encoding="utf-8")
        else:
            qpath.unlink(missing_ok=True)
    except OSError:
        pass


def collect_status_map(
    root: Path,
    gcs_accounts: list[dict[str, Any]],
    shooter_accounts: list[dict[str, Any]],
) -> dict[tuple[str, str], dict[str, str]]:
    """Legacy: pool+id → status (old GCS/Shooter tabs)."""
    out: dict[tuple[str, str], dict[str, str]] = {}
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    for acc in gcs_accounts:
        aid = str(acc.get("id") or "")
        if aid:
            out[("gcs", aid)] = {"status": _session_status(Path(acc["session"])), "notes": "", "at": now}
    for acc in shooter_accounts:
        aid = str(acc.get("id") or "")
        if aid:
            out[("shooter", aid)] = {"status": _session_status(Path(acc["session"])), "notes": "", "at": now}
    return out


def _col_index(headers: list[str], *names: str) -> int | None:
    targets = {n.lower() for n in names}
    for i, h in enumerate(headers):
        if _norm_header(h) in targets:
            return i
    return None


def _col_to_a1(col_1based: int) -> str:
    n = int(col_1based)
    out = ""
    while n > 0:
        n, rem = divmod(n - 1, 26)
        out = chr(65 + rem) + out
    return out


def _is_quota_error(exc: BaseException) -> bool:
    msg = str(exc).lower()
    return ("429" in msg) or ("quota" in msg and "exceed" in msg) or ("rate" in msg and "limit" in msg)


def _batch_update_with_retry(ws, updates: list[dict[str, Any]]) -> None:
    if not updates:
        return
    retries = max(0, int(os.environ.get("GOOGLE_SHEET_BATCH_RETRIES", "4").strip() or "4"))
    base_sleep = max(0.2, float(os.environ.get("GOOGLE_SHEET_BATCH_BASE_SLEEP_SEC", "1.0").strip() or "1.0"))
    last_err: BaseException | None = None
    for attempt in range(retries + 1):
        try:
            ws.batch_update(updates, value_input_option="USER_ENTERED")
            return
        except Exception as e:
            last_err = e
            if attempt >= retries or not _is_quota_error(e):
                raise
            sleep_s = min(base_sleep * (2**attempt), 30.0)
            time.sleep(sleep_s)
    if last_err:
        raise last_err


def push_status_to_sheet(
    root: Path,
    status_map: dict[tuple[str, str], dict[str, str]] | None = None,
    *,
    gcs_accounts: list[dict[str, Any]] | None = None,
    shooter_accounts: list[dict[str, Any]] | None = None,
) -> int:
    if use_telegram_acc_format():
        if gcs_accounts is None or shooter_accounts is None:
            return 0
        by_phone = collect_status_by_phone(root, gcs_accounts, shooter_accounts)
        return _push_telegram_acc(root, by_phone, delta_only=False)

    if not status_map:
        return 0
    wb = open_workbook(root)
    updated = 0
    for tab, pool_key in ((_tab_gcs(), "gcs"), (_tab_shooter(), "shooter")):
        try:
            ws = wb.worksheet(tab)
        except Exception:
            continue
        values = ws.get_all_values()
        if len(values) < 1:
            continue
        headers = values[0]
        id_col = _col_index(headers, "id")
        st_col = _col_index(headers, "status")
        notes_col = _col_index(headers, "notes")
        if id_col is None:
            continue
        for r_idx, line in enumerate(values[1:], start=2):
            if id_col >= len(line):
                continue
            aid = str(line[id_col]).strip()
            key = (pool_key, aid)
            if key not in status_map:
                continue
            info = status_map[key]
            if st_col is not None:
                ws.update_cell(r_idx, st_col + 1, info.get("status", ""))
            if notes_col is not None and info.get("notes"):
                ws.update_cell(r_idx, notes_col + 1, info["notes"])
            updated += 1
    qpath = status_queue_path(root)
    if updated and qpath.is_file():
        try:
            qpath.unlink(missing_ok=True)
        except OSError:
            pass
    return updated


def push_status_delta(
    root: Path,
    *,
    gcs_accounts: list[dict[str, Any]] | None = None,
    shooter_accounts: list[dict[str, Any]] | None = None,
) -> tuple[int, int]:
    """
    Push queue changes only (live-status).
    Returns (updated_rows, queued_phones).
    Does not open Google Sheet when the queue is empty.
    """
    if gcs_accounts is None or shooter_accounts is None:
        return 0, 0
    by_phone = collect_status_from_queue(root, gcs_accounts, shooter_accounts)
    queued = len(by_phone)
    if not by_phone:
        return 0, 0
    updated = _push_telegram_acc(root, by_phone, delta_only=True)
    return updated, queued


def _push_telegram_acc(
    root: Path,
    by_phone: dict[str, dict[str, str]],
    *,
    delta_only: bool = False,
) -> int:
    if not by_phone:
        return 0
    headers, lines = read_telegram_acc_tab(root)
    wb = open_workbook(root)
    if not headers:
        headers, lines = _read_tab_raw(wb, _tab_telegram())

    phone_col = _col_index(headers, "phone")
    group_col = _col_index(headers, "group")
    st_col = _status_column_index(headers)
    sf_col = _col_index(headers, "session_friday")
    if phone_col is None:
        return 0
    if st_col is None:
        print('  ⚠ Column "Status" not found in Sheet.', file=sys.stderr, flush=True)
        return 0

    ws = wb.worksheet(_tab_telegram())
    changed: list[dict[str, Any]] = []
    updated_phones: set[str] = set()
    sheet_phones_seen: set[str] = set()

    for r_idx, line in enumerate(lines, start=2):
        if phone_col >= len(line):
            continue
        phone = norm_phone(str(line[phone_col]))
        if not phone:
            continue
        row_group = str(line[group_col]).strip() if group_col is not None and group_col < len(line) else ""
        info = _lookup_status_info(by_phone, phone, row_group)
        if not info:
            continue
        sheet_phones_seen.add(phone)
        status_new = str(info.get("session_user", "") or info.get("status", "") or "").strip()
        if status_new.lower() == "unknown":
            status_new = ""
        sf_new = str(info.get("session_friday", "") or "").strip()
        if not status_new:
            status_new = _derive_status_from_session(sf_new)
        old_st = str(line[st_col]).strip() if st_col < len(line) else ""
        old_sf = str(line[sf_col]).strip() if (sf_col is not None and sf_col < len(line)) else ""

        if delta_only:
            if not status_new and not sf_new:
                continue
            row_changed = False
            if (
                status_new
                and st_col is not None
                and _script_may_write_status(old_st, status_new)
            ):
                changed.append(
                    {"range": f"{_col_to_a1(st_col + 1)}{r_idx}", "values": [[status_new]]}
                )
                row_changed = True
            if (
                sf_new
                and sf_col is not None
                and not _skip_sheet_status_write(old_sf, sf_new)
            ):
                changed.append(
                    {"range": f"{_col_to_a1(sf_col + 1)}{r_idx}", "values": [[sf_new]]}
                )
                row_changed = True
            if row_changed or (
                _skip_sheet_status_write(old_st, status_new)
                and _skip_sheet_status_write(old_sf, sf_new)
            ):
                updated_phones.add(phone)
            continue

        st_val = status_new or old_st
        sf_val = sf_new or old_sf

        skip_st = not status_new or not _script_may_write_status(old_st, st_val)
        skip_sf = not sf_new or _skip_sheet_status_write(old_sf, sf_val)
        if skip_st and skip_sf:
            continue

        if skip_st:
            st_val = old_st
        if skip_sf:
            sf_val = old_sf

        if old_st == st_val and old_sf == sf_val:
            continue

        if st_col is not None and sf_col is not None and not skip_st and not skip_sf:
            start_col = min(st_col, sf_col) + 1
            end_col = max(st_col, sf_col) + 1
            left_val = st_val if start_col == st_col + 1 else sf_val
            right_val = sf_val if end_col == sf_col + 1 else st_val
            rng = f"{_col_to_a1(start_col)}{r_idx}:{_col_to_a1(end_col)}{r_idx}"
            changed.append({"range": rng, "values": [[left_val, right_val]]})
        else:
            if not skip_st and st_col is not None:
                changed.append(
                    {"range": f"{_col_to_a1(st_col + 1)}{r_idx}", "values": [[st_val]]}
                )
            if not skip_sf and sf_col is not None:
                changed.append(
                    {"range": f"{_col_to_a1(sf_col + 1)}{r_idx}", "values": [[sf_val]]}
                )
        updated_phones.add(phone)

    if changed:
        batch_size = max(1, int(os.environ.get("GOOGLE_SHEET_BATCH_SIZE", "40").strip() or "40"))
        pause_s = max(0.0, float(os.environ.get("GOOGLE_SHEET_BATCH_PAUSE_SEC", "0.25").strip() or "0.25"))
        for i in range(0, len(changed), batch_size):
            chunk = changed[i : i + batch_size]
            _batch_update_with_retry(ws, chunk)
            if pause_s > 0 and i + batch_size < len(changed):
                time.sleep(pause_s)
        invalidate_sheet_cache()

    updated = len(updated_phones)
    trim_phones = set(updated_phones)
    if delta_only:
        orphan = {p for p in by_phone if p not in sheet_phones_seen}
        if orphan:
            trim_phones |= orphan
            sample = ", ".join(sorted(orphan)[:5])
            extra = f" (+{len(orphan) - 5})" if len(orphan) > 5 else ""
            print(
                f"  ⚠ Queue dropped {len(orphan)} phone(s) not in Sheet: {sample}{extra}",
                file=sys.stderr,
                flush=True,
            )
    if trim_phones:
        _trim_status_queue(root, trim_phones)
        compact_status_queue(root)
    return updated


def reconcile_json_vs_sheet(
    root: Path,
    *,
    gcs_accounts: list[dict[str, Any]],
    shooter_accounts: list[dict[str, Any]],
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """
    Compare JSON phones vs Sheet tab Telegram Acc.
    Returns (missing_in_sheet, missing_in_json).
    """
    headers, lines = read_telegram_acc_tab(root, force=True)
    sheet_by_phone: dict[str, dict[str, str]] = {}
    for line in lines:
        if not any(str(c).strip() for c in line):
            continue
        row = _row_dict(headers, line)
        phone = norm_phone(row.get("phone", ""))
        if phone:
            sheet_by_phone[phone] = row

    json_rows: list[dict[str, str]] = []
    for pool, accounts in (("GCS", gcs_accounts), ("SHOOTER", shooter_accounts)):
        for acc in accounts:
            if not isinstance(acc, dict):
                continue
            phone = norm_phone(str(acc.get("phone") or ""))
            if not phone:
                continue
            json_rows.append(
                {
                    "id": str(acc.get("id") or ""),
                    "phone": phone,
                    "pool": pool,
                    "profile": str(acc.get("profile_hint") or acc.get("id") or ""),
                    "brand": str(acc.get("brand") or ""),
                }
            )

    json_phones = {r["phone"] for r in json_rows}
    missing_in_sheet = [r for r in json_rows if r["phone"] not in sheet_by_phone]
    missing_in_json: list[dict[str, str]] = []
    for phone, row in sorted(sheet_by_phone.items()):
        if phone in json_phones:
            continue
        missing_in_json.append(
            {
                "phone": phone,
                "name": str(row.get("acc_name") or row.get("profile_hint") or ""),
                "status": effective_row_status(row),
                "group": str(row.get("group") or ""),
            }
        )
    return missing_in_sheet, missing_in_json


def ensure_sheet_tabs(root: Path) -> None:
    if use_telegram_acc_format():
        print(f'  Tab "{_tab_telegram()}" already exists in your Sheet — no need to recreate.')
        return
    wb = open_workbook(root)
    headers_gcs = ["id", "phone", "profile_hint", "api_id", "api_hash", "password", "brand", "enabled", "status", "notes"]
    headers_sh = ["id", "owner", "phone", "profile_hint", "password", "brand", "enabled", "status", "notes"]
    for tab, headers in ((_tab_gcs(), headers_gcs), (_tab_shooter(), headers_sh)):
        try:
            wb.worksheet(tab)
        except Exception:
            ws = wb.add_worksheet(title=tab, rows=1000, cols=len(headers) + 2)
            ws.update("A1", [headers])
