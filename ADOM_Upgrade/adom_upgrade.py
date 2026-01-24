import requests
import time
import urllib3
from datetime import datetime, timezone

# Suppress warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Configuration ---
HOST = "FMG IP"
USER = "FMG Admin"
PASS = "Admin Pass"
URL = f"https://{HOST}/jsonrpc"

# ADOMs to skip
UPGRADE_IGNORE = {
    "rootp", "Unmanaged_Devices", "Syslog", "FortiClient", "FortiProxy",
    "FortiSandbox", "FortiAuthenticator", "FortiCache", "FortiDDoS",
    "FortiDeceptor", "FortiAnalyzer", "FortiMail", "FortiManager",
    "FortiWeb", "FortiNAC", "others"
}


def now_iso():
    """Returns current UTC timestamp (replaces deprecated utcnow)"""
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')


def fmg_rpc(method, url, data=None, session=None, params_extra=None):
    """Generic JSON-RPC helper for FortiManager API"""
    params = {"url": url}
    if data: params["data"] = data
    if params_extra: params.update(params_extra)
    payload = {"id": 1, "method": method, "params": [params]}
    if session: payload["session"] = session

    response = requests.post(URL, json=payload, verify=False, timeout=20)
    return response.json()


# 1. LOGIN
login_res = fmg_rpc("exec", "/sys/login/user", data={"user": USER, "passwd": PASS})
session_id = login_res.get("session")

if not session_id:
    print(f"[{now_iso()}] LOGIN FAILED. Check credentials/connectivity.")
    exit()

print(f"[{now_iso()}] LOGIN SUCCESS. Session: {session_id[:10]}...")

try:
    # 2. GET FMG TARGET VERSION
    status_res = fmg_rpc("get", "/sys/status", session=session_id)
    s_data = status_res.get("result", [{}])[0].get("data", {})
    target_ver = f"{s_data.get('Major')}.{s_data.get('Minor')}"
    print(f"[{now_iso()}] FMG SYSTEM VERSION: {target_ver}")

    # 3. FETCH ADOMS
    adom_params = {"fields": ["name", "os_ver", "mr", "restricted_prds", "oid"], "option": "name"}
    adom_res = fmg_rpc("get", "/dvmdb/adom", session=session_id, params_extra=adom_params)
    adoms = adom_res.get("result", [{}])[0].get("data", [])

    for adom in adoms:
        name = adom.get("name")
        oid = adom.get("oid")
        raw_prods = adom.get("restricted_prds")

        # Version Logic: major.mr (e.g., 7.2)
        major = int(str(adom.get("os_ver", "0")).split(".")[0])
        minor = int(adom.get("mr", 0))
        current_ver_str = f"{major}.{minor}"

        # DETERMINING STEP TARGET (Sequential n+1)
        # If ADOM is 7.2 and FMG is 7.6, the NEXT step is 7.4
        if major == 7 and f"{major}.{minor}" != target_ver:
            next_minor = minor + 2
            step_target = f"7.{next_minor}"
        else:
            step_target = target_ver

        # BITMASK LOGIC: 1 = FortiOS (FortiGate)
        is_fos = (raw_prods == 1)

        # UPGRADE CONDITIONS
        if is_fos and name not in UPGRADE_IGNORE and current_ver_str != target_ver:
            print(f"[{now_iso()}] >>> UPGRADING ADOM: {name} ({current_ver_str} -> {step_target})")

            # TRIGGER UPGRADE
            up_url = f"/pm/config/adom/{oid}/_upgrade"
            up_exec = fmg_rpc("exec", up_url, session=session_id)

            try:
                task_id = up_exec['result'][0]['data']['task']
                # POLLING LOOP
                while True:
                    task_res = fmg_rpc("get", f"/task/task/{task_id}", session=session_id)
                    t_data = task_res.get("result", [{}])[0].get("data", {})
                    percent = t_data.get("percent", 0)

                    print(f"    Task {task_id} Progress: {percent}%", end='\r')

                    if int(percent) >= 100:
                        print(f"\n[{now_iso()}] SUCCESS: {name} finished step to {step_target}")
                        break
                    time.sleep(2)
            except (KeyError, IndexError):
                print(f"[{now_iso()}] FAILED to start task for {name}")

        else:
            # Skip Logging
            reason = "Ignored" if name in UPGRADE_IGNORE else "Up-to-date" if current_ver_str == target_ver else "Not FortiOS"
            print(f"[{now_iso()}] Skipping {name:<15} | Reason: {reason:<15} | Type: {raw_prods}")

    # 4. UPGRADE GLOBAL DATABASE
    print(f"[{now_iso()}] Checking Global Database (OID 10) upgrade...")
    fmg_rpc("exec", "/pm/config/adom/10/_upgrade", session=session_id)

finally:
    # 5. LOGOUT
    fmg_rpc("exec", "/sys/logout", session=session_id)
    print(f"[{now_iso()}] SESSION CLOSED.")
