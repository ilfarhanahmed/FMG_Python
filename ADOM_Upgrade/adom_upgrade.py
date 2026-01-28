import requests
import time
import urllib3
from datetime import datetime, timezone

# Suppress warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Configuration ---
HOST = "XXX.XXX.XXX.XXX"  # Enter your FortiManager IP here
USER = "admin"            # Enter your API/Admin username
PASS = "YOUR_PASSWORD"    # Enter your password
URL = f"https://{HOST}/jsonrpc"

# 1. Product Filter (The Bitmask mechanism)
SUPPORTED_PRODUCT_TYPES = {
    1,                  # FortiGate (FortiOS)
    2,                  # FortiCarrier
    8192,               # FortiProxy
    32768,              # FortiFirewall
    8388608,            # FortiFirewallCarrier
    4503599627370495    # Fabric ADOM / Security Fabric
}

# 2. Safety List
UPGRADE_IGNORE = {
    "rootp", "Unmanaged_Devices", "Syslog", "FortiClient", 
    "FortiSandbox", "FortiAuthenticator", "FortiCache", "FortiDDoS", 
    "FortiDeceptor", "FortiAnalyzer", "FortiMail", "FortiManager", 
    "FortiWeb", "others"
}

def now_iso():
    """Returns current UTC timestamp using timezone-aware objects."""
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

def fmg_rpc(method, url, data=None, session=None, params_extra=None):
    """Generic JSON-RPC helper for FortiManager API."""
    params = {"url": url}
    if data: params["data"] = data
    if params_extra: params.update(params_extra)
    payload = {"id": 1, "method": method, "params": [params]}
    if session: payload["session"] = session

    response = requests.post(URL, json=payload, verify=False, timeout=20)
    return response.json()

def wait_for_task(task_id, session_id, adom_name):
    """Polls the Task Manager until the given task_id is 100% complete."""
    while True:
        task_res = fmg_rpc("get", f"/task/task/{task_id}", session=session_id)
        t_data = task_res.get("result", [{}])[0].get("data", {})
        percent = t_data.get("percent", 0)
        print(f"    Task {task_id} Progress: {percent}%", end='\r')
        if int(percent) >= 100:
            print(f"\n[{now_iso()}] SUCCESS: {adom_name} operation finished.")
            break
        time.sleep(2)

# --- START EXECUTION ---

# 1. LOGIN
login_res = fmg_rpc("exec", "/sys/login/user", data={"user": USER, "passwd": PASS})
session_id = login_res.get("session")

if not session_id:
    print(f"[{now_iso()}] LOGIN FAILED.")
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

    # 4. ITERATE THROUGH ADOMS
    for adom in adoms:
        name = adom.get("name")
        oid = adom.get("oid")
        raw_prods = adom.get("restricted_prds")

        # Skip Global (OID 10) for now, we do it at the very end
        if str(oid) == "10": continue

        major = int(str(adom.get("os_ver", "0")).split(".")[0])
        minor = int(adom.get("mr", 0))
        current_ver_str = f"{major}.{minor}"

        if major == 7 and current_ver_str != target_ver:
            step_target = f"7.{minor + 2}"
        else:
            step_target = target_ver

        if raw_prods in SUPPORTED_PRODUCT_TYPES and name not in UPGRADE_IGNORE and current_ver_str != target_ver:
            print(f"[{now_iso()}] >>> UPGRADING {name} ({current_ver_str} -> {step_target})")
            up_exec = fmg_rpc("exec", f"/pm/config/adom/{oid}/_upgrade", session=session_id)
            try:
                wait_for_task(up_exec['result'][0]['data']['task'], session_id, name)
            except:
                print(f"[{now_iso()}] FAILED to start task for {name}")
        else:
            reason = "Ignored" if name in UPGRADE_IGNORE else "Up-to-date" if current_ver_str == target_ver else "Unsupported Type"
            print(f"[{now_iso()}] Skipping {name:<20} | Reason: {reason}")

    # --- 5. GLOBAL DATABASE UPGRADE (FINAL STEP) ---
    # Global ADOM is usually OID 10. We check its version and upgrade it last.
    print(f"---")
    print(f"[{now_iso()}] Initiating Global Database Upgrade (OID 10)...")
    global_res = fmg_rpc("get", "/dvmdb/adom/10", session=session_id)
    g_data = global_res.get("result", [{}])[0].get("data", {})
    g_ver = f"{str(g_data.get('os_ver', '0')).split('.')[0]}.{g_data.get('mr', 0)}"

    if g_ver != target_ver:
        global_up = fmg_rpc("exec", "/pm/config/adom/10/_upgrade", session=session_id)
        try:
            wait_for_task(global_up['result'][0]['data']['task'], session_id, "Global Database")
        except:
            print(f"[{now_iso()}] Global Upgrade Task could not be initiated.")
    else:
        print(f"[{now_iso()}] Global Database is already at version {target_ver}.")

finally:
    if session_id:
        fmg_rpc("exec", "/sys/logout", session=session_id)
        print(f"[{now_iso()}] SESSION CLOSED.")
