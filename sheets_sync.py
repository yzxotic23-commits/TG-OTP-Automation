"""
Google Sheets ↔ accounts.json / shooteraccounts.json
Tab utama: "Telegram Acc" (format operasional kamu).
"""
from __future__ import annotations

import json
import os
import re
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
    "status": frozenset({"status", "state", "feeding_status"}),
    # Kolom Sheet "Account Status" (bukan "Session User")
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
    "password": frozenset({"password", "2fa", "twofa"}),
    "brand": frozenset({"brand"}),
    "owner": frozenset({"owner"}),
    "enabled": frozenset({"enabled", "active"}),
    "notify_account": frozenset({"notify_account", "notify"}),
    "session": frozenset({"session", "session_path"}),
    "notes": frozenset({"notes", "note", "remark", "remarks"}),
}

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


def norm_phone(raw: str) -> str:
    """60123456789 → +60123456789"""
    d = re.sub(r"\D", "", str(raw or ""))
    if not d:
        return ""
    if d.startswith("00"):
        d = d[2:]
    if not d.startswith("+"):
        return "+" + d
    return d


def _pool_from_group(group_val: str) -> str | None:
    """
    Kolom Group di Sheet:
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
    """Owner shooter dari kolom User (Venus → VENNUS, …)."""
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
    """Map kolom User Sheet -> accounts[].id (untuk notify_account GCS)."""
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
    """True = pakai tab Telegram Acc (default jika GOOGLE_SHEET_ID di-set)."""
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
    """Langsung ke Sheet untuk masalah akun — Active cukup di cycle sync."""
    su = _map_script_status(session_user)
    return su in (
        "Banned",
        "Frozen",
        "Expired",
        "Disconnected",
        "Pending Login",
    )


def classify_account_status(exc: BaseException | None = None, *, message: str = "") -> str:
    """
    Status akun Telegram untuk kolom Account Status (bukan Session Friday).
  """
    if exc is not None:
        name = type(exc).__name__.lower()
        msg = str(exc).lower()
    else:
        name = ""
        msg = str(message or "").lower()

    combined = f"{name} {msg}"
    if "phonenumberbanned" in name or "userdeactivatedban" in name or "banned" in combined:
        return "Banned"
    if "frozen" in combined or "freeze" in combined or "frozen_participant" in combined:
        return "Frozen"
    if "account_banned" in combined or "user_banned" in combined:
        return "Banned"
    if "userdeactivated" in name or "deactivated" in combined:
        return "Banned"
    if "authkeyunregistered" in name or "sessionrevoked" in name or "auth key" in combined:
        return "Expired"
    if "password" in combined and "needed" in combined:
        return "Pending Login"
    if "expired" in combined or "not authorized" in combined:
        return "Expired"
    if "disconnect" in combined:
        return "Disconnected"
    if message:
        return _map_script_status(message) or "Unknown"
    return "Expired"


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
) -> None:
    """
    Antrian untuk push ke Sheet.
    session_user  → kolom Account Status (Active/Banned/Frozen/…)
    session_friday → kolom Session Friday (session bot FRIDAY_BO saja)
    `status` = fallback untuk session_user jika session_user kosong.
    """
    path = status_queue_path(root)
    su = _map_script_status(session_user or status)
    sf = _map_script_status(session_friday) if session_friday else ""
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

    if instant_push_enabled() and row.get("phone") and _should_instant_push(su):
        import threading

        threading.Thread(
            target=_instant_push_worker,
            args=(root, row["phone"], su, sf, account_id),
            daemon=True,
        ).start()


def _instant_push_worker(
    root: Path,
    phone: str,
    session_user: str,
    session_friday: str,
    account_id: str,
) -> None:
    try:
        if push_status_instant(root, phone, session_user, session_friday):
            label = account_id or phone
            friday_part = f" | Friday: {session_friday}" if session_friday else ""
            print(
                f"  📋 Google Sheet updated · {label} → Account Status: {session_user}{friday_part}",
                flush=True,
            )
    except Exception as e:
        print(f"  ⚠ Google Sheet instant push failed: {e}", file=sys.stderr, flush=True)


def push_status_instant(
    root: Path,
    phone: str,
    session_user: str,
    session_friday: str = "",
) -> bool:
    """Update satu baris di tab Telegram Acc (by Phone Number)."""
    if not _sheet_id() or not use_telegram_acc_format():
        return False
    np = norm_phone(phone)
    if not np:
        return False
    su = _map_script_status(session_user)
    sf = _map_script_status(session_friday) if session_friday else "Pending Login"
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
            "Lalu share Google Sheet ke email service account (Editor)."
        ) from e
    return gspread, Credentials


def open_workbook(root: Path):
    gspread, Credentials = _load_gspread()
    cred_path = _credentials_path(root)
    if not cred_path.is_file():
        raise FileNotFoundError(f"Credentials not found: {cred_path}")
    sid = _sheet_id()
    if not sid:
        raise ValueError("Set GOOGLE_SHEET_ID in .env (ID dari URL Google Sheet).")
    scopes = ["https://www.googleapis.com/auth/spreadsheets"]
    creds = Credentials.from_service_account_file(str(cred_path), scopes=scopes)
    gc = gspread.authorize(creds)
    return gc.open_by_key(sid)


def _read_tab_raw(wb, tab_name: str) -> tuple[list[str], list[list[str]]]:
    try:
        ws = wb.worksheet(tab_name)
    except Exception:
        return [], []
    values = ws.get_all_values()
    if len(values) < 1:
        return [], []
    return values[0], values[1:]


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


def _new_gcs_id(phone: str, acc_name: str, existing: list[dict[str, Any]]) -> str:
    suffix = re.sub(r"\D", "", phone)[-4:] or "0000"
    name = str(acc_name or "").strip()
    if len(name) > 2:
        slug = re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").upper()
        if slug and not slug.replace("_", "").isdigit():
            base = slug[:24]
        else:
            base = f"GCS_{suffix}"
    else:
        base = f"GCS_{suffix}"
    ids = {str(r.get("id") or "") for r in existing if isinstance(r, dict)}
    if base not in ids:
        return base
    n = 2
    while f"{base}_{n}" in ids:
        n += 1
    return f"{base}_{n}"


def _new_shooter_id(owner: str, phone: str, existing: list[dict[str, Any]]) -> str:
    owner_u = owner or "UNKNOWN"
    suffix = re.sub(r"\D", "", phone)[-4:] or "0000"
    base = f"SH_{owner_u}_{suffix}"
    ids = {str(r.get("id") or "") for r in existing if isinstance(r, dict)}
    if base not in ids:
        return base
    n = 2
    while f"{base}_{n}" in ids:
        n += 1
    return f"{base}_{n}"


def _telegram_row_to_gcs(
    row: dict[str, str], raw: dict[str, Any], existing: list[dict[str, Any]]
) -> dict[str, Any] | None:
    """Baris Group=Main → otp_accounts (GCS)."""
    if _pool_from_group(row.get("group", "")) != "gcs":
        return None
    phone = norm_phone(row.get("phone", ""))
    if not phone:
        return None
    channel = str(row.get("channel") or "").lower()
    if channel and "telegram" not in channel:
        return None

    matched = _find_by_phone(existing, phone)
    api_id, api_hash = _resolve_gcs_api(row, raw, existing, matched)
    if not api_id or not api_hash:
        return None

    acc_name = row.get("acc_name") or row.get("profile_hint") or ""
    account_status = str(row.get("session_user") or "").strip()
    aid = str(matched.get("id") if matched else "").strip()
    if not aid:
        aid = _new_gcs_id(phone, acc_name, existing)

    enabled = _truthy(row.get("enabled", "1"))
    if _session_user_disabled(account_status):
        enabled = False

    session_default = f"telegram_session/{aid}"
    out: dict[str, Any] = {
        "id": aid,
        "phone": phone,
        "api_id": int(api_id),
        "api_hash": api_hash,
        "enabled": enabled,
        "session": (matched.get("session") if matched else None) or session_default,
        "notify_account": _resolve_notify_account_from_user(raw, row.get("user", ""), matched),
    }
    if acc_name:
        out["profile_hint"] = acc_name
    if row.get("password"):
        out["password"] = row["password"]
    if row.get("device_id"):
        out["brand"] = str(row.get("device_id", "")).split("-")[0].upper() or None
    return out


def _telegram_row_to_shooter(row: dict[str, str], raw: dict[str, Any], existing: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Baris Group=Other → shooter_accounts."""
    if _pool_from_group(row.get("group", "")) != "shooter":
        return None
    phone = norm_phone(row.get("phone", ""))
    if not phone:
        return None
    channel = str(row.get("channel") or "").lower()
    if channel and "telegram" not in channel:
        return None

    owner = _normalize_owner_name(row.get("user") or row.get("owner") or "")
    acc_name = row.get("acc_name") or row.get("profile_hint") or ""
    account_status = str(row.get("session_user") or "").strip()

    matched = _find_by_phone(existing, phone)
    aid = str(matched.get("id") if matched else "").strip()
    if not aid:
        if not owner:
            return None
        aid = _new_shooter_id(owner, phone, existing)

    enabled = _truthy(row.get("enabled", "1"))
    if _session_user_disabled(account_status):
        enabled = False

    session_default = f"telegram_session/shooter/{aid}"
    out: dict[str, Any] = {
        "id": aid,
        "phone": phone,
        "owner": owner or (str(matched.get("owner") if matched else "") or "UNKNOWN"),
        "enabled": enabled,
        "session": (matched.get("session") if matched else None) or session_default,
    }
    if acc_name:
        out["profile_hint"] = acc_name
    if row.get("device_id"):
        out["remark"] = str(row.get("device_id") or "")
    return out


def _pull_telegram_acc(
    wb,
    mutate_accounts: Callable[[dict[str, Any]], bool],
    mutate_shooter: Callable[[dict[str, Any]], bool],
) -> dict[str, int]:
    headers, lines = _read_tab_raw(wb, _tab_telegram())
    stats = {
        "shooter_added": 0, "shooter_updated": 0, "shooter_skipped": 0,
        "gcs_added": 0, "gcs_updated": 0, "gcs_skipped": 0,
    }

    def _apply_gcs(data: dict[str, Any]) -> None:
        nonlocal stats
        lst = data.setdefault("otp_accounts", [])
        if not isinstance(lst, list):
            lst = []
            data["otp_accounts"] = lst
        for line in lines:
            if not any(str(c).strip() for c in line):
                continue
            row = _row_dict(headers, line)
            entry = _telegram_row_to_gcs(row, data, lst)
            if not entry:
                if _pool_from_group(row.get("group", "")) == "gcs":
                    stats["gcs_skipped"] += 1
                continue
            phone = entry["phone"]
            before = _find_by_phone(lst, phone) is not None
            _upsert_list(lst, entry, key="id")
            if before:
                stats["gcs_updated"] += 1
            else:
                stats["gcs_added"] += 1

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
            entry = _telegram_row_to_shooter(row, data, lst)
            if not entry:
                if _pool_from_group(row.get("group", "")) == "shooter":
                    stats["shooter_skipped"] += 1
                continue
            phone = entry["phone"]
            before = _find_by_phone(lst, phone) is not None
            _upsert_list(lst, entry, key="id")
            if before:
                stats["shooter_updated"] += 1
            else:
                stats["shooter_added"] += 1

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
    st = row.get("session_user") or row.get("status") or ""
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
    st = row.get("session_user") or row.get("status") or ""
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
) -> dict[str, int]:
    wb = open_workbook(root)
    if use_telegram_acc_format():
        return _pull_telegram_acc(wb, mutate_accounts, mutate_shooter)

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


def _map_script_status(st: str) -> str:
    s = str(st or "").strip().lower()
    mapping = {
        "active": "Active",
        "pending_login": "Pending Login",
        "expired": "Expired",
        "disconnected": "Disconnected",
        "banned": "Banned",
        "frozen": "Frozen",
        "freeze": "Frozen",
    }
    return mapping.get(s, st.title() if st else "")


def collect_status_by_phone(
    root: Path,
    gcs_accounts: list[dict[str, Any]],
    shooter_accounts: list[dict[str, Any]],
) -> dict[str, dict[str, str]]:
    """
    phone → {session_user, session_friday, …}

    Account Status = status akun (Active / Banned / Frozen / Expired / …)
    Session Friday = session bot FRIDAY_BO saja (Active / Disconnected / Pending Login)
    """
    out: dict[str, dict[str, str]] = {}
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")

    def _add(acc: dict[str, Any], pool: str) -> None:
        phone = norm_phone(str(acc.get("phone") or ""))
        if not phone:
            return
        # Friday = apakah file session bot ada (belum tentu akun banned)
        friday = _session_status(Path(acc["session"]))
        out[phone] = {
            "session_user": "Unknown",
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
                pool = str(ev.get("pool") or "")
                su = _map_script_status(
                    str(ev.get("session_user") or ev.get("status") or "")
                )
                sf = _map_script_status(str(ev.get("session_friday") or ""))
                if not su and not sf:
                    continue
                key_phone = phone
                if not key_phone and aid:
                    for p, info in out.items():
                        if info.get("account_id") == aid:
                            key_phone = p
                            break
                if not key_phone:
                    continue
                prev = out.get(key_phone, {})
                out[key_phone] = {
                    "session_user": su or prev.get("session_user", "Unknown"),
                    "session_friday": sf or prev.get("session_friday", ""),
                    "notes": str(ev.get("note") or prev.get("notes") or ""),
                    "at": str(ev.get("at") or now),
                    "account_id": aid or prev.get("account_id", ""),
                    "pool": pool or prev.get("pool", ""),
                }
        except (OSError, json.JSONDecodeError):
            pass
    return out


def collect_status_map(
    root: Path,
    gcs_accounts: list[dict[str, Any]],
    shooter_accounts: list[dict[str, Any]],
) -> dict[tuple[str, str], dict[str, str]]:
    """Legacy: pool+id → status (untuk tab GCS/Shooter lama)."""
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
        return _push_telegram_acc(root, by_phone)

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


def _push_telegram_acc(root: Path, by_phone: dict[str, dict[str, str]]) -> int:
    if not by_phone:
        return 0
    wb = open_workbook(root)
    headers, lines = _read_tab_raw(wb, _tab_telegram())
    if not headers:
        return 0

    phone_col = _col_index(headers, "phone")
    su_col = _col_index(headers, "session_user")
    sf_col = _col_index(headers, "session_friday")
    if phone_col is None:
        return 0
    if su_col is None:
        print('  ⚠ Kolom "Account Status" tidak ditemukan di Sheet.', file=sys.stderr, flush=True)
        return 0

    ws = wb.worksheet(_tab_telegram())
    updated = 0

    for r_idx, line in enumerate(lines, start=2):
        if phone_col >= len(line):
            continue
        phone = norm_phone(str(line[phone_col]))
        if not phone or phone not in by_phone:
            continue
        info = by_phone[phone]
        # Account Status = laporan script (Active / Banned / Frozen / …)
        su_val = info.get("session_user", "") or "Unknown"
        # Session Friday = session bot FRIDAY_BO
        sf_val = info.get("session_friday", "") or "Pending Login"

        if su_col is not None:
            ws.update_cell(r_idx, su_col + 1, su_val)
        if sf_col is not None:
            ws.update_cell(r_idx, sf_col + 1, sf_val)
        updated += 1

    qpath = status_queue_path(root)
    if updated and qpath.is_file():
        try:
            qpath.unlink(missing_ok=True)
        except OSError:
            pass
    return updated


def ensure_sheet_tabs(root: Path) -> None:
    if use_telegram_acc_format():
        print(f'  Tab "{_tab_telegram()}" sudah ada di Sheet kamu — tidak perlu dibuat ulang.')
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
