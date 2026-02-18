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

EXPORT_DIR = "./fmg_exports"   # where export script saved files
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
        json=payload,
        verify=False
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
        json=payload,
        verify=False
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
        json=payload,
        verify=False
    )
    resp.raise_for_status()
    print(f"[{now_iso()}] Switched to ADOM OID {oid}.")


def prompt_adom_selection(session, csrf_token):
    """Default root, optional switch; hides Global ADOM (OID 10)."""
    choice = input("\nDefault ADOM is Root (OID=3). Do you want to change ADOM? [y/N]: ").strip().lower()
    if choice != "y":
        print(f"[{now_iso()}] Proceeding with Root ADOM (OID=3).")
        return DEFAULT_ADOM_OID, "root"

    print(f"\n[{now_iso()}] Fetching ADOM list...")
    adoms = list_adoms(session, csrf_token)

    if not adoms:
        print("No ADOMs returned. Falling back to Root ADOM.")
        return DEFAULT_ADOM_OID, "root"

    # Filter out Global ADOM (OID 10)
    adoms = [a for a in adoms if str(a.get("oid")) != "10"]

    if not adoms:
        print("Only Global ADOM present; falling back to Root ADOM (3).")
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


def prompt_import_file():
    """
    Ask user for the exported file name only and look for it under EXPORT_DIR.
    """
    base_dir = EXPORT_DIR
    print(f"\nAvailable files in {base_dir}:")
    if os.path.isdir(base_dir):
        for fname in os.listdir(base_dir):
            print(f"  - {fname}")
    else:
        print(f"  (Directory does not exist yet: {base_dir})")

    while True:
        name = input("\nEnter export file name (as listed above): ").strip()
        file_path = os.path.join(base_dir, name)
        if os.path.isfile(file_path):
            print(f"[{now_iso()}] Using import file: {file_path}")
            return file_path
        print(f"  File not found: '{file_path}'. Please try again.")


def upload_template_file(session, csrf_token, file_path):
    print(f"[{now_iso()}] Uploading template file: {file_path}")
    with open(file_path, "rb") as f:
        files = {"filepath": (os.path.basename(file_path), f, "application/json")}
        data = {
            "csrfmiddlewaretoken": csrf_token,
            "csrf_token":         csrf_token,
        }
        resp = session.post(
            f"{BASE_URL}/flatui/api/gui/deploy/import",
            headers={
                "XSRF-TOKEN": csrf_token,
                "Referer": f"{BASE_URL}/ui/dvm/prvtmpl/clitmpl"
            },
            data=data,
            files=files,
            verify=False
        )
    resp.raise_for_status()
    print(f"[{now_iso()}] File uploaded successfully.")
    return resp.json()


def execute_import(session, csrf_token, adom_oid):
    print(f"[{now_iso()}] Executing template import for ADOM OID {adom_oid}...")
    payload = {
        "method": "exec",
        "params": [{
            "url": "/deployment/import/template",
            "data": {
                "adom": adom_oid,
                "file": "/var/tmp/deploy_import",
                "create_task": "true"
            }
        }],
        "id": "6"
    }
    resp = session.post(
        f"{BASE_URL}/cgi-bin/module/flatui/json",
        headers={"XSRF-TOKEN": csrf_token},
        json=payload,
        verify=False
    )
    resp.raise_for_status()
    data = resp.json()
    result_data = data.get("data", {}).get("result", [{}])[0].get("data", {})
    task_id  = result_data.get("taskid")
    file_name = result_data.get("file")

    if not task_id:
        raise RuntimeError(f"Import execution failed. Response: {data}")

    print(f"[{now_iso()}] Import task created. Task ID: {task_id}")
    return task_id, file_name


def wait_for_task(session, csrf_token, task_id, poll_interval=3, timeout=180):
    """
    Poll task until FMG marks it finished. Returns the full task dict
    (including line/history) for reporting.
    """
    print(f"[{now_iso()}] Polling task {task_id}...", end="", flush=True)
    deadline = time.time() + timeout
    last_task = {}

    while time.time() < deadline:
        payload = {
            "method": "get",
            "params": [{"url": f"/task/task/{task_id}"}],
            "id": "3"
        }
        resp = session.post(
            f"{BASE_URL}/cgi-bin/module/flatui/forward",
            headers={"XSRF-TOKEN": csrf_token},
            json=payload,
            verify=False
        )
        resp.raise_for_status()
        raw = resp.json()

        # Try both response shapes: result[0].data or data.result[0].data
        try:
            task = raw["result"][0]["data"]
        except (KeyError, IndexError, TypeError):
            try:
                task = raw["data"]["result"][0]["data"]
            except (KeyError, IndexError, TypeError):
                task = {}

        last_task = task

        percent   = task.get("percent", 0)
        state     = task.get("state", -1)   # 4 = success, 5 = finished with errors
        num_done  = task.get("num_done", 0)
        num_lines = task.get("num_lines", -1)

        print(f" {percent}%", end="", flush=True)

        done = state in (4, 5, "4", "5") or percent == 100 or (num_lines > 0 and num_done >= num_lines)
        if done:
            print(f"\n[{now_iso()}] Task {task_id} finished (state={state}).")
            return task

        if state in (2, "2"):
            raise RuntimeError(f"Task {task_id} reported an explicit error state: {task}")

        time.sleep(poll_interval)

    raise TimeoutError(f"Task {task_id} did not complete within {timeout}s. Last payload: {last_task}")


def print_import_report(adom_oid, adom_name, task_id, file_path, task_result, duration_sec):
    task_state    = task_result.get("state", "N/A")
    task_percent  = task_result.get("percent", "N/A")
    lines_list    = task_result.get("line", []) or []
    history_list  = task_result.get("history", []) or []

    error_entries = []

    # Per-step errors often show up in 'detail' with text like "mismatch", "invalid", etc.
    for entry in lines_list:
        err = entry.get("err", 0)
        detail = entry.get("detail") or entry.get("msg") or ""
        if err != 0 or ("error" in detail.lower()) or ("mismatch" in detail.lower()) or ("invalid" in detail.lower()):
            error_entries.append(entry)

    for entry in history_list:
        err = entry.get("err", 0)
        detail = entry.get("detail") or entry.get("msg") or ""
        if err != 0 or ("error" in detail.lower()) or ("mismatch" in detail.lower()) or ("invalid" in detail.lower()):
            error_entries.append(entry)

    # Treat anything not state==4 or with error entries as failure
    has_errors = len(error_entries) > 0 or str(task_state) not in ("4",)

    lines = [
        "",
        "=" * 65,
        "       FORTIMANAGER TEMPLATE IMPORT REPORT",
        "=" * 65,
        f"  Timestamp   : {now_iso()}",
        f"  FMG Host    : {HOST}",
        f"  ADOM        : {adom_name} (OID: {adom_oid})",
        f"  Task ID     : {task_id}",
        f"  Source File : {file_path}",
        f"  Duration    : {duration_sec:.1f}s",
        "-" * 65,
        f"  Overall Task State : {task_state}",
        f"  Progress           : {task_percent}%",
    ]

    if has_errors:
        lines.append("-" * 65)
        lines.append("  ERRORS DETECTED:")
        if not error_entries:
            lines.append("    - Task state indicates error, but no line/history details were found.")
        else:
            for e in error_entries:
                detail = e.get("detail") or e.get("msg") or ""
                lines.append(f"    - {detail}")
    else:
        lines.append("-" * 65)
        lines.append("  Result: SUCCESS")

    lines.append("=" * 65)
    print("\n".join(lines))


# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    session = requests.Session()
    start = time.time()
    csrf_token = None

    try:
        csrf_token = login(session)
        adom_oid, adom_name = prompt_adom_selection(session, csrf_token)

        file_path = prompt_import_file()
        upload_template_file(session, csrf_token, file_path)

        task_id, _ = execute_import(session, csrf_token, adom_oid)
        task_result = wait_for_task(session, csrf_token, task_id)

        duration = time.time() - start
        print_import_report(
            adom_oid, adom_name, task_id,
            file_path, task_result, duration
        )

    except Exception as e:
        print(f"\n[ERROR] {e}")
        raise
    finally:
        if csrf_token:
            logout(session, csrf_token)


if __name__ == "__main__":
    main()
