import requests
import time
import urllib3
import json
import os
from datetime import datetime, timezone

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── Configuration ────────────────────────────────────────────────────────────
HOST     = "FMG IP"
ADMIN    = "admin"
PASSWORD = "admin password"
BASE_URL = f"https://{HOST}"
DEFAULT_ADOM_OID = 3   # Root ADOM

TEMPLATE_CATEGORIES = [
    "ap-prof", "bgp-prof", "bonjour-prof", "cli-prof", "cert-prof", "dev-blueprint",
    "fext-prof", "switch-prof", "ips-prof", "ipsec-prof",
    "cst-prof", "qos-prof", "sdwan-overlay-prof", "sdwan-prof",
    "route-prof", "sys-prof", "tmplgrp-prof", "cr-prof"
]

EXPORT_DIR = "./fmg_exports"
# ──────────────────────────────────────────────────────────────────────────────


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def login(session):
    print(f"[{now_iso()}] Logging in to FortiManager at {HOST}...")
    payload = {
        "url": "/gui/userauth",
        "method": "login",
        "params": {
            "username": ADMIN,
            "secretkey": PASSWORD,
            "logintype": 0
        }
    }
    resp = session.post(
        f"{BASE_URL}/cgi-bin/module/flatui_auth",
        json=payload, verify=False
    )
    resp.raise_for_status()
    data = resp.json()
    status = data.get("result", [{}])[0].get("status", {})
    if status.get("code") != 0:
        raise RuntimeError(f"Login failed: {status.get('message', 'Unknown error')}")

    csrf_token = session.cookies.get("HTTP_CSRF_TOKEN")
    if not csrf_token:
        raise RuntimeError("CSRF token not found in cookies after login.")

    print(f"[{now_iso()}] Login successful. CSRF token acquired.")
    return csrf_token


def logout(session, csrf_token):
    print(f"[{now_iso()}] Logging out...")
    session.post(
        f"{BASE_URL}/p/logout-api/",
        headers={
            "XSRF-TOKEN": csrf_token,
            "Referer": BASE_URL
        },
        verify=False
    )
    print(f"[{now_iso()}] Logged out.")


def list_adoms(session, csrf_token):
    payload = {
        "url": "/gui/switch/adoms/list",
        "method": "get",
        "params": {}
    }
    resp = session.post(
        f"{BASE_URL}/cgi-bin/module/flatui_proxy",
        headers={"XSRF-TOKEN": csrf_token},
        json=payload, verify=False
    )
    resp.raise_for_status()
    data = resp.json()
    return data.get("result", [{}])[0].get("data", [])


def switch_adom(session, csrf_token, oid):
    payload = {
        "url": "/gui/session/adom",
        "method": "change",
        "params": {"oid": oid}
    }
    resp = session.post(
        f"{BASE_URL}/cgi-bin/module/flatui_proxy",
        headers={"XSRF-TOKEN": csrf_token},
        json=payload, verify=False
    )
    resp.raise_for_status()
    print(f"[{now_iso()}] Switched to ADOM OID {oid}.")


def prompt_adom_selection(session, csrf_token):
    choice = input("\nDefault ADOM is Root (OID=3). Do you want to change ADOM? [y/N]: ").strip().lower()
    if choice != "y":
        print(f"[{now_iso()}] Proceeding with Root ADOM (OID=3).")
        return DEFAULT_ADOM_OID, "root"

    print(f"\n[{now_iso()}] Fetching ADOM list...")
    adoms = list_adoms(session, csrf_token)

    if not adoms:
        print("No ADOMs returned. Falling back to Root ADOM.")
        return DEFAULT_ADOM_OID, "root"

    print(f"\n{'#':<4} {'Name':<30} {'OID':<8} {'Version':<12} {'Type'}")
    print("-" * 65)
    for i, adom in enumerate(adoms):
        ver = adom.get("version", {})
        ver_str = f"{ver.get('ver', '?')}.{ver.get('mr', '?')}"
        print(f"{i+1:<4} {adom.get('name', 'N/A'):<30} {adom.get('oid', 'N/A'):<8} {ver_str:<12} {adom.get('type_name', 'N/A')}")

    while True:
        try:
            idx = int(input("\nEnter the # of the ADOM to switch to: ")) - 1
            if 0 <= idx < len(adoms):
                selected = adoms[idx]
                oid = selected["oid"]
                name = selected["name"]
                switch_adom(session, csrf_token, oid)
                return oid, name
            else:
                print("Invalid selection, try again.")
        except ValueError:
            print("Please enter a valid number.")


def initiate_export(session, csrf_token, adom_oid):
    print(f"\n[{now_iso()}] Initiating template export for ADOM OID {adom_oid}...")
    payload = {
        "method": "exec",
        "params": [{
            "url": "/deployment/export/template",
            "data": {
                "adom": adom_oid,
                "category": TEMPLATE_CATEGORIES,
                "create_task": "true"
            }
        }],
        "id": "1"
    }
    resp = session.post(
        f"{BASE_URL}/cgi-bin/module/flatui/forward",
        headers={"XSRF-TOKEN": csrf_token},
        json=payload, verify=False
    )
    resp.raise_for_status()
    data = resp.json()
    result_data = data.get("data", {}).get("result", [{}])[0].get("data", {})
    task_id   = result_data.get("taskid")
    file_name = result_data.get("file")

    if not task_id:
        raise RuntimeError(f"Export initiation failed. Response: {data}")

    print(f"[{now_iso()}] Export task created. Task ID: {task_id}, File: {file_name}")
    return task_id, file_name


def wait_for_task(session, csrf_token, task_id, poll_interval=3, timeout=120):
    print(f"[{now_iso()}] Polling task {task_id}...", end="", flush=True)
    deadline = time.time() + timeout
    while time.time() < deadline:
        payload = {
            "method": "get",
            "params": [{"url": f"/task/task/{task_id}"}],
            "id": "3"
        }
        resp = session.post(
            f"{BASE_URL}/cgi-bin/module/flatui/forward",
            headers={"XSRF-TOKEN": csrf_token},
            json=payload, verify=False
        )
        resp.raise_for_status()

        raw = resp.json()

        try:
            task = raw["result"][0]["data"]
        except (KeyError, IndexError, TypeError):
            try:
                task = raw["data"]["result"][0]["data"]
            except (KeyError, IndexError, TypeError):
                task = {}

        # ── Uncomment to debug the live task payload ───────────────────
        # print(f"\nDEBUG task payload: {json.dumps(task, indent=2)}")

        percent   = task.get("percent", 0)
        state     = task.get("state", -1)
        num_done  = task.get("num_done", 0)
        num_lines = task.get("num_lines", -1)

        print(f" {percent}%", end="", flush=True)

        if state in (4, "4") or percent == 100 or (num_lines > 0 and num_done >= num_lines):
            print(f"\n[{now_iso()}] Task {task_id} completed successfully.")
            return task

        if state in (2, "2"):
            raise RuntimeError(f"Task {task_id} reported an error state. Response: {task}")

        time.sleep(poll_interval)

    raise TimeoutError(f"Task {task_id} did not complete within {timeout}s.")


def download_export(session, csrf_token, task_id, file_name):
    """
    Request 6 — GET /flatui/api/gui/deploy/export
    Downloads the actual template export bundle from FMG.
    Saves the raw response content as-is — no extra text added.
    """
    os.makedirs(EXPORT_DIR, exist_ok=True)
    download_name = f"{task_id}_{file_name}"
    local_path = os.path.join(EXPORT_DIR, download_name)

    print(f"[{now_iso()}] Downloading export file...")
    resp = session.get(
        f"{BASE_URL}/flatui/api/gui/deploy/export",
        headers={
            "XSRF-TOKEN": csrf_token,
            "Referer": f"{BASE_URL}/ui/dvm/prvtmpl/clitmpl"
        },
        params={
            "filename":     file_name,
            "downloadname": download_name
        },
        verify=False
    )
    resp.raise_for_status()

    # ── Save raw response bytes exactly as received — no modifications ─
    with open(local_path, "wb") as f:
        f.write(resp.content)

    print(f"[{now_iso()}] Export file saved to: {local_path}")
    return local_path, download_name


def print_console_report(adom_oid, adom_name, task_id, file_name,
                          local_path, categories, duration_sec):
    """Prints a human-readable summary to console only. Nothing is written to file here."""
    lines = [
        "",
        "=" * 65,
        "       FORTIMANAGER TEMPLATE EXPORT REPORT",
        "=" * 65,
        f"  Timestamp   : {now_iso()}",
        f"  FMG Host    : {HOST}",
        f"  ADOM        : {adom_name} (OID: {adom_oid})",
        f"  Task ID     : {task_id}",
        f"  Export File : {file_name}",
        f"  Saved To    : {local_path}",
        f"  Duration    : {duration_sec:.1f}s",
        "-" * 65,
        f"  Categories Exported ({len(categories)}):",
    ]
    for cat in categories:
        lines.append(f"    ✔  {cat}")
    lines.append("=" * 65)
    print("\n".join(lines))


# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    session = requests.Session()
    csrf_token = None
    start = time.time()

    try:
        csrf_token = login(session)
        adom_oid, adom_name = prompt_adom_selection(session, csrf_token)

        task_id, file_name = initiate_export(session, csrf_token, adom_oid)
        wait_for_task(session, csrf_token, task_id)
        local_path, _ = download_export(session, csrf_token, task_id, file_name)

        duration = time.time() - start
        print_console_report(
            adom_oid, adom_name, task_id, file_name,
            local_path, TEMPLATE_CATEGORIES, duration
        )

    except Exception as e:
        print(f"\n[ERROR] {e}")
        raisen
    finally:
        if csrf_token:
            logout(session, csrf_token)


if __name__ == "__main__":
    main()
