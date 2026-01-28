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

# 1. Upgradable ADOM Mapping
UPGRADABLE_ADOMS = {
    1: "FortiGate (FortiOS)",
    2: "FortiCarrier",
    8192: "FortiProxy",
    32768: "FortiFirewall",
    8388608: "FortiFirewallCarrier",
    4503599627370495: "Fabric",
    "Global": "Global Database (OID 10)"
}

# 2. Safety List
UPGRADE_IGNORE = {
    "rootp", "Unmanaged_Devices", "Syslog", "FortiClient",
    "FortiSandbox", "FortiAuthenticator", "FortiCache", "FortiDDoS",
    "FortiDeceptor", "FortiAnalyzer", "FortiMail", "FortiManager",
    "FortiWeb", "others"
}


def now_iso():
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')


def fmg_rpc(method, url, data=None, session=None, params_extra=None):
    params = {"url": url}
    if data: params["data"] = data
    if params_extra: params.update(params_extra)
    payload = {"id": 1, "method": method, "params": [params]}
    if session: payload["session"] = session
    response = requests.post(URL, json=payload, verify=False, timeout=20)
    return response.json()


def wait_for_task(task_id, session_id, adom_name):
    while True:
        task_res = fmg_rpc("get", f"/task/task/{task_id}", session=session_id)
        t_data = task_res.get("result", [{}])[0].get("data", {})
        percent = t_data.get("percent", 0)
        print(f"    Task {task_id} Progress: {percent}%", end='\r')
        if int(percent) >= 100:
            print()
            print(f"[{now_iso()}] SUCCESS: {adom_name} operation finished.")
            break
        time.sleep(2)


# --- EXECUTION ---
login_res = fmg_rpc("exec", "/sys/login/user", data={"user": USER, "passwd": PASS})
session_id = login_res.get("session")

if not session_id:
    print(f"[{now_iso()}] LOGIN FAILED.")
    exit()

try:
    # 1. Get FMG System Ceiling
    status_res = fmg_rpc("get", "/sys/status", session=session_id)
    fmg_max_ver = f"{status_res['result'][0]['data']['Major']}.{status_res['result'][0]['data']['Minor']}"
    print(f"[{now_iso()}] FMG SYSTEM VERSION: {fmg_max_ver}")

    # 2. Fetch ADOM metadata
    adom_params = {"fields": ["name", "os_ver", "mr", "restricted_prds", "oid"], "option": "name"}
    adom_res = fmg_rpc("get", "/dvmdb/adom", session=session_id, params_extra=adom_params)
    adoms = adom_res.get("result", [{}])[0].get("data", [])

    # Identify Global version first to set the safety gate
    global_data = next((a for a in adoms if str(a.get('oid')) == "10"), None)
    g_ver = f"{str(global_data.get('os_ver')).split('.')[0]}.{global_data.get('mr')}"

    print(f"[{now_iso()}] CURRENT GLOBAL VERSION: {g_ver}")

    # 3. UPGRADE CHILD ADOMS
    global_upgrade_blocked = False

    for adom in adoms:
        name, oid, raw_prods = adom.get("name"), adom.get("oid"), adom.get("restricted_prds")
        if str(oid) == "10": continue

        major = int(str(adom.get("os_ver", "0")).split(".")[0])
        minor = int(adom.get("mr", 0))
        current_ver = f"{major}.{minor}"

        if raw_prods in UPGRADABLE_ADOMS.keys() and name not in UPGRADE_IGNORE:
            if current_ver != fmg_max_ver:
                step_target = f"7.{minor + 2}" if major == 7 else fmg_max_ver
                if float(step_target) > float(fmg_max_ver): step_target = fmg_max_ver

                print(f"[{now_iso()}] >>> UPGRADING {name} ({current_ver} -> {step_target})")
                up_exec = fmg_rpc("exec", f"/pm/config/adom/{oid}/_upgrade", session=session_id)
                try:
                    wait_for_task(up_exec['result'][0]['data']['task'], session_id, name)
                    # Update local data for the final report
                    adom['os_ver'] = step_target.split('.')[0]
                    adom['mr'] = step_target.split('.')[1]
                    current_ver = step_target
                except:
                    print(f"[{now_iso()}] FAILED to start task for {name}")

            # Safety Gate: If any child is still behind current Global version, block Global upgrade
            if float(current_ver) < float(g_ver):
                global_upgrade_blocked = True
        else:
            print(f"[{now_iso()}] Skipping {name:<20} | Status: Non-upgradable or Ignored")

    # --- 4. CONDITIONAL GLOBAL UPGRADE ---
    print("-" * 30)
    if g_ver == fmg_max_ver:
        print(f"[{now_iso()}] Global Database is already at FMG Max ({fmg_max_ver}).")
    elif global_upgrade_blocked:
        print(
            f"[{now_iso()}] GUARD ACTIVE: Global upgrade skipped. One or more ADOMs are still on a version lower than {g_ver}.")
    else:
        g_step = f"7.{int(global_data.get('mr')) + 2}" if int(
            str(global_data.get('os_ver')).split('.')[0]) == 7 else fmg_max_ver
        if float(g_step) > float(fmg_max_ver): g_step = fmg_max_ver

        print(f"[{now_iso()}] VERIFIED: No children behind Global. Upgrading Global ({g_ver} -> {g_step})...")
        global_up = fmg_rpc("exec", "/pm/config/adom/10/_upgrade", session=session_id)
        if global_up.get("result", [{}])[0].get("status", {}).get("code") == 0:
            wait_for_task(global_up['result'][0]['data']['task'], session_id, "Global Database")
            # Update global_data for the final report
            global_data['os_ver'] = g_step.split('.')[0]
            global_data['mr'] = g_step.split('.')[1]
        else:
            print(f"[{now_iso()}] Global Upgrade Task initiation failed.")

    # --- 5. FINAL SUMMARY REPORT ---
    print("\n" + "=" * 80)
    print(f"{'FINAL ADOM STATUS REPORT':^80}")
    print("=" * 80)
    print(f"{'ADOM Name':<30} | {'Product Type':<25} | {'Version':<10}")
    print("-" * 80)

    # Sort for cleaner output (Global first or last)
    for adom in sorted(adoms, key=lambda x: str(x.get('oid')) == "10"):
        name = adom.get('name')
        oid = str(adom.get('oid'))
        raw_prods = adom.get('restricted_prds')

        # Resolve Type Name
        if oid == "10":
            type_name = UPGRADABLE_ADOMS["Global"]
        else:
            type_name = UPGRADABLE_ADOMS.get(raw_prods, "Other / Non-Upgradable")

        ver_str = f"{str(adom.get('os_ver')).split('.')[0]}.{adom.get('mr')}"
        print(f"{name:<30} | {type_name:<25} | {ver_str:<10}")
    print("=" * 80)

finally:
    if 'session_id' in locals() and session_id:
        fmg_rpc("exec", "/sys/logout", session=session_id)
        print(f"[{now_iso()}] SESSION CLOSED. DISCONNECTED.")
