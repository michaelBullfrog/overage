import os
import json
import time
import asyncio
import random
import logging
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional
from datetime import datetime, timezone

now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
header = f"📅 **{now}**\n"


import httpx
from fastapi import FastAPI
from apscheduler.schedulers.asyncio import AsyncIOScheduler


# ============================================================
# CONFIG (use environment variables; do NOT hardcode secrets)
# ============================================================
WEBEX_CLIENT_ID = ("C764fb80894c93c6b21dd540cf13b14915ea239c89ec4cb43b793eff7cd686b5f")
WEBEX_CLIENT_SECRET = ("cf8ed8b26a589764413937de72baa7e52a03e5cf9d8e09db64b4da020e38553f")
WEBEX_REDIRECT_URI = ("https://overage.onrender.com/oauth/callback")

# Alert room (Webex space/room ID)
WEBEX_ALERT_ROOM_ID = ("Y2lzY29zcGFyazovL3VzL1JPT00vYjAwZTg4MDAtZTAzYi0xMWYwLThjMTctMGI2Yjc1ZDAyOTFl")

# Optional: temporary testing token via env (NOT recommended for long term)
HARDCODED_ACCESS_TOKEN = ("ZDM3MjRlYzMtNjk0YS00YWVlLWJkMGEtNTk5NzU2MWNiMjE4YjI1MDQ2MzgtZmEz_PF84_7726209c-42bf-4dd2-a7ed-6f1139040882")

# Schedule (minutes)
CHECK_EVERY_MINUTES = int(os.getenv("CHECK_EVERY_MINUTES", "1440"))

# Reporting controls
POST_SUMMARY_EVERY_RUN = ("POST_SUMMARY_EVERY_RUN", "true")
POST_CHANGES_ONLY = ("POST_CHANGES_ONLY", "true")  # if true, only post change-alert when changes exist
POST_TOP_OFFENDERS = ("POST_TOP_OFFENDERS", "true")
POST_FULL_OVERAGE_LIST = ("POST_FULL_OVERAGE_LIST", "true")
TOP_N = int(os.getenv("TOP_N", "50"))

# Files (local persistence)
TOKENS_FILE = Path("webex_tokens.json")
STATE_FILE = Path("overage_state.json")

# Webex API base
WEBEX_API = "https://webexapis.com/v1"

# Networking / stability
HTTP_TIMEOUT = httpx.Timeout(connect=15.0, read=45.0, write=45.0, pool=15.0)
MAX_RETRIES = int(os.getenv("WEBEX_MAX_RETRIES", "4"))
ORG_CONCURRENCY = int(os.getenv("ORG_CONCURRENCY", "5"))
ORG_CALL_SEMAPHORE = asyncio.Semaphore(ORG_CONCURRENCY)

EXCLUDED_LICENSE_KEYWORDS = [
    "Basic Meetings",
    "Webex Basic",
    "Meetings Basic",
    "Advanced Messaging",
]

# ============================================================
# Logging
# ============================================================
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger("overage-monitor")

app = FastAPI()
scheduler = AsyncIOScheduler()

webex_client: Optional[httpx.AsyncClient] = None


# ============================================================
# JSON helpers
# ============================================================
def save_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def load_json(path: Path) -> Optional[dict]:
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return None


# ============================================================
# Token persistence
# ============================================================
def save_tokens(tok: dict) -> None:
    tok["saved_at"] = int(time.time())
    save_json(TOKENS_FILE, tok)


def load_tokens() -> Optional[dict]:
    return load_json(TOKENS_FILE)


# ============================================================
# Webex HTTP client
# ============================================================
async def get_webex_client() -> httpx.AsyncClient:
    global webex_client
    if webex_client is None:
        webex_client = httpx.AsyncClient(timeout=HTTP_TIMEOUT)
        logger.info("🌐 Webex HTTP client initialized")
    return webex_client


async def webex_get(access_token: str, path: str, params: dict | None = None) -> dict:
    client = await get_webex_client()
    url = f"{WEBEX_API}{path}"
    headers = {"Authorization": f"Bearer {access_token}"}

    last_exc: Optional[Exception] = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            r = await client.get(url, headers=headers, params=params)
            r.raise_for_status()
            return r.json()
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout, httpx.RemoteProtocolError) as e:
            last_exc = e
            sleep_s = min(10.0, (2 ** (attempt - 1)) + random.random())
            logger.warning(f"⏱️ Webex {type(e).__name__} {path} attempt {attempt}/{MAX_RETRIES} (sleep {sleep_s:.1f}s)")
            await asyncio.sleep(sleep_s)

    raise last_exc or RuntimeError(f"webex_get failed: {path}")


async def webex_post(access_token: str, path: str, payload: dict) -> dict:
    client = await get_webex_client()
    url = f"{WEBEX_API}{path}"
    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}

    last_exc: Optional[Exception] = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            r = await client.post(url, headers=headers, json=payload)
            r.raise_for_status()
            return r.json()
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout, httpx.RemoteProtocolError) as e:
            last_exc = e
            sleep_s = min(10.0, (2 ** (attempt - 1)) + random.random())
            logger.warning(f"⏱️ Webex {type(e).__name__} {path} attempt {attempt}/{MAX_RETRIES} (sleep {sleep_s:.1f}s)")
            await asyncio.sleep(sleep_s)

    raise last_exc or RuntimeError(f"webex_post failed: {path}")


# ============================================================
# OAuth endpoints
# ============================================================
@app.get("/oauth/callback")
async def oauth_callback(code: str, state: str | None = None):
    """
    Webex redirects here with ?code=...
    Exchange that code for access/refresh tokens and save locally.
    """
    if not WEBEX_CLIENT_ID or not WEBEX_CLIENT_SECRET:
        return {"ok": False, "error": "Missing WEBEX_CLIENT_ID/WEBEX_CLIENT_SECRET (env vars)"}

    token_url = f"{WEBEX_API}/access_token"
    data = {
        "grant_type": "authorization_code",
        "client_id": WEBEX_CLIENT_ID,
        "client_secret": WEBEX_CLIENT_SECRET,
        "code": code,
        "redirect_uri": WEBEX_REDIRECT_URI,
    }

    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(token_url, data=data)
    r.raise_for_status()

    tok = r.json()
    save_tokens(tok)
    logger.info("✅ OAuth complete. Tokens saved to webex_tokens.json")
    return {"ok": True, "message": "Tokens saved. You can close this tab.", "expires_in": tok.get("expires_in")}


async def refresh_webex_token(refresh_token: str) -> dict:
    if not WEBEX_CLIENT_ID or not WEBEX_CLIENT_SECRET:
        raise RuntimeError("Missing WEBEX_CLIENT_ID/WEBEX_CLIENT_SECRET (env vars)")

    token_url = f"{WEBEX_API}/access_token"
    data = {
        "grant_type": "refresh_token",
        "client_id": WEBEX_CLIENT_ID,
        "client_secret": WEBEX_CLIENT_SECRET,
        "refresh_token": refresh_token,
    }
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(token_url, data=data)
    r.raise_for_status()

    tok = r.json()
    save_tokens(tok)
    logger.info("🔄 Refreshed access token")
    return tok


async def get_valid_access_token() -> str:
    # TEMP: allow hardcoded token for testing
    if HARDCODED_ACCESS_TOKEN:
        return HARDCODED_ACCESS_TOKEN

    tok = load_tokens()
    if not tok:
        raise RuntimeError("No tokens found. Run OAuth flow first and hit /oauth/callback")

    saved_at = int(tok.get("saved_at", 0))
    expires_in = int(tok.get("expires_in", 0))
    if int(time.time()) > (saved_at + expires_in - 300):
        tok = await refresh_webex_token(tok["refresh_token"])

    return tok["access_token"]


# ============================================================
# Partner org + license usage
# ============================================================
async def list_orgs(access_token: str) -> List[Dict[str, Any]]:
    """
    /organizations is paginated via Link headers.
    """
    items: List[Dict[str, Any]] = []
    url = f"{WEBEX_API}/organizations"
    headers = {"Authorization": f"Bearer {access_token}"}

    client = await get_webex_client()

    while url:
        r = await client.get(url, headers=headers)
        r.raise_for_status()
        data = r.json()
        items.extend(data.get("items", []))

        # Parse Link header for next
        link = r.headers.get("Link", "")
        next_url = None
        if 'rel="next"' in link:
            parts = [p.strip() for p in link.split(",")]
            for p in parts:
                if 'rel="next"' in p:
                    next_url = p.split(";")[0].strip().strip("<>").strip()
                    break
        url = next_url

    return items


async def get_licenses_for_org(access_token: str, org_id: str) -> List[Dict[str, Any]]:
    async with ORG_CALL_SEMAPHORE:
        data = await webex_get(access_token, "/licenses", params={"orgId": org_id})
        return data.get("items", [])


# ============================================================
# Webex room alerting
# ============================================================
async def post_alert(access_token: str, markdown: str) -> None:
    room_id = (WEBEX_ALERT_ROOM_ID or "").strip()
    if not room_id:
        logger.error("❌ WEBEX_ALERT_ROOM_ID is missing/empty. Skipping alert.")
        return

    # Webex can 400 on oversized messages. Keep chunks safe.
    MAX_CHARS = 6500
    text = (markdown or "").strip()
    if not text:
        return

    chunks: List[str] = []
    while len(text) > MAX_CHARS:
        cut = text.rfind("\n", 0, MAX_CHARS)
        if cut <= 0:
            cut = MAX_CHARS
        chunks.append(text[:cut])
        text = text[cut:].lstrip("\n")
    if text:
        chunks.append(text)

    for chunk in chunks:
        payload = {"roomId": room_id, "markdown": chunk}
        try:
            await webex_post(access_token, "/messages", payload)
        except httpx.HTTPStatusError as e:
            body = ""
            try:
                body = e.response.text
            except Exception:
                pass
            logger.error(f"❌ Webex post failed ({e.response.status_code}): {body[:500]}")
            return


# ============================================================
# Overage state & diff
# ============================================================
def load_state() -> dict:
    return load_json(STATE_FILE) or {}


def save_state(state: dict) -> None:
    save_json(STATE_FILE, state)


def build_overage_state(orgs: List[dict], org_licenses: Dict[str, List[dict]]) -> dict:
    """
    state key: orgId|licenseId
    value: org name, license name, purchased, assigned, overage
    """
    state: dict = {}
    org_name_map = {o["id"]: o.get("displayName", o["id"]) for o in orgs}

    for org_id, licenses in org_licenses.items():
        org_name = org_name_map.get(org_id, org_id)
        for lic in licenses:
            license_name = (lic.get("name") or "").strip()
            # 🚫 Skip excluded / non-billable licenses (e.g., Basic Meetings)
            if any(k.lower() in license_name.lower() for k in EXCLUDED_LICENSE_KEYWORDS):
                continue
            purchased = int(lic.get("totalUnits") or 0)
            assigned = int(lic.get("consumedUnits") or 0)
            overage = max(assigned - purchased, 0)

            key = f"{org_id}|{lic.get('id')}"
            state[key] = {
                "orgId": org_id,
                "org": org_name,
                "licenseId": lic.get("id"),
                "license": lic.get("name", lic.get("id")),
                "purchased": purchased,
                "assigned": assigned,
                "overage": overage,
                "ts": int(time.time()),
            }
    return state


def diff_overages(prev: dict, cur: dict) -> Tuple[List[dict], List[dict]]:
    new_or_increased: List[dict] = []
    cleared: List[dict] = []

    for k, item in cur.items():
        if int(item.get("overage", 0)) <= 0:
            continue
        old = prev.get(k)
        if not old:
            new_or_increased.append({"type": "NEW", "item": item})
        else:
            old_over = int(old.get("overage", 0))
            if int(item.get("overage", 0)) > old_over:
                new_or_increased.append({"type": "INCREASED", "from": old_over, "to": int(item["overage"]), "item": item})

    for k, old in prev.items():
        old_over = int(old.get("overage", 0))
        if old_over <= 0:
            continue
        now = cur.get(k)
        now_over = int(now.get("overage", 0)) if now else 0
        if now_over == 0:
            cleared.append({"type": "CLEARED", "item": old})

    return new_or_increased, cleared


# ============================================================
# Main scheduled job
# ============================================================
async def run_check():
    try:
        access_token = await get_valid_access_token()

        orgs = await list_orgs(access_token)
        logger.info(f"🔢 Total orgs found: {len(orgs)}")

        # Fetch licenses for each org (concurrency limited)
        org_licenses: Dict[str, List[dict]] = {}
        denied_orgs: List[str] = []
        errored_orgs: List[str] = []

        async def fetch_one(o: dict):
            org_id = o["id"]
            org_name = o.get("displayName", org_id)
            try:
                org_licenses[org_id] = await get_licenses_for_org(access_token, org_id)
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 403:
                    denied_orgs.append(org_name)
                    org_licenses[org_id] = []
                    logger.warning(f"⛔ 403 (no access): {org_name}")
                else:
                    errored_orgs.append(org_name)
                    org_licenses[org_id] = []
                    logger.warning(f"⚠️ HTTP {e.response.status_code} for {org_name}: {e.response.text[:200]}")
            except Exception as e:
                errored_orgs.append(org_name)
                org_licenses[org_id] = []
                logger.warning(f"⚠️ Error for {org_name}: {e}")

        # Run with bounded concurrency via semaphore in get_licenses_for_org
        await asyncio.gather(*(fetch_one(o) for o in orgs))

        prev_state = load_state()
        cur_state = build_overage_state(orgs, org_licenses)
        new_or_increased, cleared = diff_overages(prev_state, cur_state)

        over_items = [v for v in cur_state.values() if int(v.get("overage", 0)) > 0]
        over_orgs = len({v["orgId"] for v in over_items})
        over_items_sorted = sorted(over_items, key=lambda x: int(x.get("overage", 0)), reverse=True)

        # --------------------------
        # Build posts (each section is ONE post; no duplicates)
        # --------------------------
        if POST_SUMMARY_EVERY_RUN:
            summary_lines = [
                header +
                "📊 **Webex Overage Monitor — Pull Summary**",
                f"• Orgs scanned: **{len(orgs)}**",
                f"• Orgs w/ overages: **{over_orgs}**",
                f"• Active overage entries: **{len(over_items)}**",
                f"• Denied (403) orgs: **{len(denied_orgs)}**",
                f"• Other errors: **{len(errored_orgs)}**",
                f"• Interval: **{CHECK_EVERY_MINUTES} min**",
            ]
            await post_alert(access_token, "\n".join(summary_lines))

        # Change alert (only when changes exist if POST_CHANGES_ONLY)
        if (not POST_CHANGES_ONLY) or (new_or_increased):
            if new_or_increased:
                lines = [header + "🚨 **Webex License Overage Update (NEW / INCREASED)**"]
                for d in new_or_increased:
                    item = d["item"]
                    if d["type"] == "NEW":
                        lines.append(
                            f"• **NEW** — {item['org']} — {item['license']} — "
                            f"Overage: **{item['overage']}** (Purchased {item['purchased']}, Assigned {item['assigned']})"
                        )
                    else:
                        lines.append(
                            f"• **INCREASED** — {item['org']} — {item['license']} — "
                            f"**{d['from']} → {d['to']}** (Purchased {item['purchased']}, Assigned {item['assigned']})"
                        )
                await post_alert(access_token, "\n".join(lines))
            else:
                await post_alert(access_token, "✅ No new/increased overages in this run.")

        if POST_TOP_OFFENDERS and over_items_sorted:
            top_lines = [f"📌 **Top Overage Offenders (Top {min(TOP_N, len(over_items_sorted))})**"]
            for v in over_items_sorted[:TOP_N]:
                top_lines.append(
                    f"• {v['org']} — {v['license']} — Overage: **{v['overage']}** "
                    f"(Purchased {v['purchased']}, Assigned {v['assigned']})"
                )
            await post_alert(access_token, "\n".join(top_lines))

        if POST_FULL_OVERAGE_LIST and over_items_sorted:
            full_lines = ["🧾 **FULL Overage List (All Active Entries)**"]
            for v in over_items_sorted:
                full_lines.append(
                    f"• {v['org']} — {v['license']} — Overage: {v['overage']} "
                    f"(Purchased {v['purchased']}, Assigned {v['assigned']})"
                )
            await post_alert(access_token, "\n".join(full_lines))

        # Persist state for diffing next run
        save_state(cur_state)

    except RuntimeError as e:
        # common case: no tokens yet
        logger.warning(f"⏭️ Skipping run_check: {e}")
    except Exception:
        logger.exception("❌ run_check crashed")


# ============================================================
# App lifecycle: scheduler
# ============================================================
@app.on_event("startup")
async def startup():
    # Basic config checks (don’t print secrets/tokens)
    if not WEBEX_CLIENT_ID or not WEBEX_CLIENT_SECRET:
        logger.warning("⚠️ WEBEX_CLIENT_ID / WEBEX_CLIENT_SECRET not set (OAuth will not work until set).")
    if not WEBEX_ALERT_ROOM_ID:
        logger.warning("⚠️ WEBEX_ALERT_ROOM_ID not set (alerts will fail).")

    # schedule job (no extra immediate run, so no duplicate posts)
    scheduler.add_job(run_check, "interval", minutes=CHECK_EVERY_MINUTES, id="run_check", coalesce=True, max_instances=1)
    scheduler.start()
    logger.info(f"✅ Scheduler started (every {CHECK_EVERY_MINUTES} minutes).")


@app.on_event("shutdown")
async def shutdown():
    global webex_client
    scheduler.shutdown(wait=False)
    if webex_client:
        await webex_client.aclose()
        webex_client = None
    logger.info("👋 Shutdown complete.")
