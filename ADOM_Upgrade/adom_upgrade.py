import requests
import time
import urllib3
from datetime import datetime, timezone

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Configuration ---
HOST = "xxxxxxxxxxxx"
USER = "xxxxxxxxx"
PASS = "xxxxxxxxxx"
URL = f"https://{HOST}/jsonrpc"

UPGRADABLE_ADOMS = {
    1: "FortiGate (FortiOS)",
    2: "FortiCarrier",
    8192: "FortiProxy",
    32768: "FortiFirewall",
    8388608: "FortiFirewallCarrier",
    4503599627370495: "Fabric",
    "Global": "Global Database (OID 10)"
}

UPGRADE_IGNORE = {
    "rootp", "Unmanaged_Devices", "Syslog", "others",
    "FortiManager", "FortiMail", "FortiAnalyzer", "FortiWeb",
    "FortiCache", "FortiSandbox", "FortiAuthenticator", "FortiClient",
    "FortiDDoS", "FortiDeceptor"
}


def now_iso():
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')


def fmg_rpc(method, url, data=None, session=None, params_extra=None):
    params = {"url": url}
    if data: params["data"] = data
    if params_extra: params.update(params_extra)
    payload = {"id": 1, "method": method, "params": [params]}
    if session: payload["session"] = session
    return requests.post(URL, json=payload, verify=False, timeout=20).json()


def wait_for_task(task_id, session_id):
    while True:
        task_res = fmg_rpc("get", f"/task/task/{task_id}", session=session_id)
        percent = task_res.get("result", [{}])[0].get("data", {}).get("percent", 0)
        print(f"    Task Progress: {percent}%", end='\r')
        if int(percent) >= 100:
            print()
            break
        time.sleep(2)


# --- EXECUTION ---
login_res = fmg_rpc("exec", "/sys/login/user", data={"user": USER, "passwd": PASS})
session_id = login_res.get("session")

try:
    # 0. Get Initial Info
    status_res = fmg_rpc("get", "/sys/status", session=session_id)
    fmg_ver = f"{status_res['result'][0]['data']['Major']}.{status_res['result'][0]['data']['Minor']}"

    adom_res = fmg_rpc("get", "/dvmdb/adom", session=session_id, params_extra={"option": "name"})
    adoms = adom_res.get("result", [{}])[0].get("data", [])

    global_data = next(a for a in adoms if str(a.get('oid')) == "10")
    g_ver_orig = f"{str(global_data.get('os_ver')).split('.')[0]}.{global_data.get('mr')}"

    print("=" * 65)
    print(f"FORTIMANAGER SYSTEM VERSION: {fmg_ver}")
    print(f"CURRENT GLOBAL ADOM VERSION: {g_ver_orig}")
    print("=" * 65)

    target_v = min(float(fmg_ver), float(g_ver_orig) + 0.2)
    target_str = f"{target_v:.1f}"

    # Track versions and upgrade status
    version_map = {}
    for a in adoms:
        v = f"{str(a.get('os_ver')).split('.')[0]}.{a.get('mr')}"
        version_map[a.get('name')] = {"prev": v, "curr": v, "upgraded": False}

    # --- PHASE 1: UPGRADE LOCAL ADOMS ---
    print(f"[{now_iso()}] STEP 1: Upgrading local ADOMS first...")

    for adom in adoms:
        name, oid, raw_prods = adom.get("name"), str(adom.get("oid")), adom.get("restricted_prds")
        if oid == "10" or name in UPGRADE_IGNORE or raw_prods not in UPGRADABLE_ADOMS:
            continue

        cur_v = float(version_map[name]["prev"])
        if cur_v < target_v:
            # Calculate the REAL next step for truthful console output
            step_v = min(target_v, cur_v + 0.2)
            step_str = f"{step_v:.1f}"

            print(f"    >>> Upgrading Local '{name}' ({cur_v} -> {step_str})")
            up_exec = fmg_rpc("exec", f"/pm/config/adom/{oid}/_upgrade", session=session_id)
            wait_for_task(up_exec['result'][0]['data']['task'], session_id)
            
            # Re-query actual ADOM version after task completion
            updated_info = fmg_rpc("get", f"/dvmdb/adom/{name}", session=session_id)
            u_data = updated_info.get("result", [{}])[0].get("data", {})
            real_v = f"{str(u_data.get('os_ver')).split('.')[0]}.{u_data.get('mr')}"
            
            version_map[name]["curr"] = real_v
            version_map[name]["upgraded"] = True if float(real_v) > cur_v else False

    # --- PHASE 2: UPGRADE GLOBAL ---
    print("-" * 65)
    all_ready = True
    for name, vdata in version_map.items():
        match_adom = next(a for a in adoms if a['name'] == name)
        if str(match_adom.get('oid')) == "10" or name in UPGRADE_IGNORE or match_adom.get(
                'restricted_prds') not in UPGRADABLE_ADOMS:
            continue
        if float(vdata["curr"]) < target_v:
            all_ready = False

    if all_ready and float(g_ver_orig) < target_v:
        # Calculate the REAL next step for truthful console output
        g_step_v = min(target_v, float(g_ver_orig) + 0.2)
        g_step_str = f"{g_step_v:.1f}"

        print(f"[{now_iso()}] STEP 2: All upgradable local ADOMs are upgraded to verified milestone.")
        print(f"[{now_iso()}] STEP 3: Now upgrading Global Database to {g_step_str}...")
        global_up = fmg_rpc("exec", "/pm/config/adom/10/_upgrade", session=session_id)
        wait_for_task(global_up['result'][0]['data']['task'], session_id)
        
        # Re-query actual Global version after task completion
        updated_g = fmg_rpc("get", "/dvmdb/adom/rootp", session=session_id)
        ug_data = updated_g.get("result", [{}])[0].get("data", {})
        real_gv = f"{str(ug_data.get('os_ver')).split('.')[0]}.{ug_data.get('mr')}"
        
        version_map[global_data.get('name')]["curr"] = real_gv
        version_map[global_data.get('name')]["upgraded"] = True if float(real_gv) > float(g_ver_orig) else False
    else:
        print(f"[{now_iso()}] GLOBAL UPGRADE: Skipped (Already at target or locals not ready).")

    # --- FINAL SUMMARY REPORT ---
    print("\n" + "=" * 110)
    print(f"{'FINAL ADOM UPGRADE STATUS REPORT':^110}")
    print("=" * 110)
    print(f"{'ADOM Name':<25} | {'Product Type':<25} | {'Prev Ver':<10} | {'Curr Ver':<10} | {'Status'}")
    print("-" * 110)


    def sort_logic(x):
        is_global = str(x.get('oid')) == "10"
        is_ignored = x.get('name') in UPGRADE_IGNORE and not is_global
        is_upgradable = x.get('restricted_prds') in UPGRADABLE_ADOMS or is_global
        if is_upgradable and not is_ignored and not is_global:
            group = 0
        elif is_global:
            group = 1
        else:
            group = 2
        return (group, x.get('name'))


    for adom in sorted(adoms, key=sort_logic):
        name = adom.get('name')
        oid = str(adom.get('oid'))
        raw_p = adom.get('restricted_prds')

        v_data = version_map[name]

        # Determine Status
        if oid == "10":
            type_n = "Global Database"
            status = "Upgraded" if v_data["upgraded"] else "Not Upgraded"
        elif raw_p in UPGRADABLE_ADOMS and name not in UPGRADE_IGNORE:
            type_n = UPGRADABLE_ADOMS[raw_p]
            status = "Upgraded" if v_data["upgraded"] else "Not Upgraded"
        else:
            type_n = "Non-Upgradable/System"
            status = "Ignored"

        print(f"{name:<25} | {type_n:<25} | {v_data['prev']:<10} | {v_data['curr']:<10} | {status}")
    print("=" * 110)

finally:
    if 'session_id' in locals():
        fmg_rpc("exec", "/sys/logout", session=session_id)
        print(f"[{now_iso()}] SESSION CLOSED.")
