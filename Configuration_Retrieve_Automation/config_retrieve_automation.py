"""
FortiManager Devices' Retrieve Configuration
Logs into FortiManager, lets you pick ADOM and device(s),
then Retrieves config.

by: Farhan Ahmed - www.farhan.ch
"""

import os
import requests
import json
import time
import sys

# Suppress insecure request warnings
requests.packages.urllib3.disable_warnings()

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'

def clear_terminal():
    os.system('cls' if os.name == 'nt' else 'clear')

def read_password(label):
    import getpass
    in_pycharm = 'PYCHARM_HOSTED' in os.environ or 'PYDEV_CONSOLE_EXECUTE_HOOK' in os.environ
    if in_pycharm:
        return input(label)
    try:
        return getpass.getpass(label)
    except Exception:
        return input(label)

def print_final_table(task_data):
    print(f"\n{Colors.BOLD}{Colors.HEADER}TASK SUMMARY{Colors.END}")
    print(f" Total: {task_data.get('num_lines', 0)}  |  "
          f"Done: {Colors.GREEN}{task_data.get('num_done', 0)}{Colors.END}  |  "
          f"Errors: {Colors.RED}{task_data.get('num_err', 0)}{Colors.END}\n")

    header = f" {'STATUS':<10} | {'DEVICE NAME':<25} | {'IP ADDRESS':<18} | {'DETAILS'}"
    print(f"{Colors.BOLD}{header}{Colors.END}")
    print(" " + "-" * (len(header) + 10))

    for entry in task_data.get('line', []):
        is_pass = entry.get('state') in ('done', 4) and entry.get('err', 0) == 0
        badge = f"{Colors.GREEN}PASS{Colors.END}" if is_pass else f"{Colors.RED}FAIL{Colors.END}"
        print(f" {badge:<19} | {entry.get('name', 'Unknown'):<25} | {entry.get('ip', 'N/A'):<18} | {entry.get('detail', '')}")
    print()

def main():
    print(f"{Colors.BLUE}{Colors.BOLD}{'=' * 60}{Colors.END}")
    print(f"{Colors.BOLD}   FORTIMANAGER RETRIEVE CONFIGURATION AUTOMATION{Colors.END}")
    print(f"{Colors.BLUE}{'=' * 60}{Colors.END}\n")

    host = input(f"{Colors.CYAN}{Colors.BOLD}FMG IP/URL:{Colors.END} ").strip()
    user = input(f"{Colors.CYAN}{Colors.BOLD}Admin Username:{Colors.END} ").strip()
    pwd = read_password(f"{Colors.CYAN}{Colors.BOLD}Admin Password:{Colors.END} ")
    base_url = f"https://{host}/jsonrpc"

    try:
        login_res = requests.post(base_url, json={"id": 1, "method": "exec", "params": [{"data": {"user": user, "passwd": pwd}, "url": "/sys/login/user"}]}, verify=False).json()
        session = login_res.get("session")
    except Exception as e:
        print(f"\n{Colors.RED}✘ Connection failed: {e}{Colors.END}")
        return

    if not session:
        print(f"\n{Colors.RED}✘ Login failed. Check credentials.{Colors.END}")
        return

    print(f"\n{Colors.GREEN}✔ Session Established.{Colors.END}")

    status_res = requests.post(base_url, json={"id": 1, "session": session, "method": "get", "params": [{"url": "/sys/status"}], "verbose": 1}, verify=False).json()
    adom_enabled = status_res['result'][0]['data'].get('Admin Domain Configuration') != 'Disabled'
    selected_adom = 'root' if not adom_enabled else None

    try:
        while True:
            # --- ADOM SELECTION ---
            if adom_enabled and not selected_adom:
                adom_res = requests.post(base_url, json={"id": 2, "session": session, "method": "get", "verbose": 1, "params": [{"url": "/dvmdb/adom", "fields": ["name", "restricted_prds"]}]}, verify=False).json()
                raw_data = adom_res['result'][0].get('data', [])

                # Updated: Use string codes as per your environment
                allowed_products = ["fos", "foc", "ffw", "fwc", "fpx"]
                filtered_adoms = []

                for a in raw_data:
                    # Skip non-dict data and exclude rootp (Global ADOM)
                    if not isinstance(a, dict) or a.get('name') == 'rootp':
                        continue

                    product_code = str(a.get('restricted_prds', '')).lower()
                    if product_code in allowed_products:
                        filtered_adoms.append(a['name'])

                if not filtered_adoms:
                    print(f"\n{Colors.YELLOW}⚠ No matching ADOMs found. Defaulting to 'root'.{Colors.END}")
                    selected_adom = 'root'
                else:
                    print(f"\n{Colors.BOLD}{Colors.HEADER}--- AVAILABLE ADOMS ---{Colors.END}")
                    for i in range(0, len(filtered_adoms), 2):
                        col1 = f"[{Colors.CYAN}{i}{Colors.END}] {filtered_adoms[i]}"
                        col2 = f"[{Colors.CYAN}{i+1}{Colors.END}] {filtered_adoms[i+1]}" if i+1 < len(filtered_adoms) else ""
                        print(f"  {col1:<35} {col2}")

                    try:
                        idx = input(f"\n{Colors.BOLD}Select ADOM Index (or 'e'xit):{Colors.END} ")
                        if idx.lower() in ('e', 'exit'):
                            sys.exit(0)
                        selected_adom = filtered_adoms[int(idx)]
                    except (ValueError, IndexError):
                        print(f"{Colors.RED}Invalid selection.{Colors.END}")
                        continue

            # --- DEVICE SELECTION ---
            dev_res = requests.post(base_url, json={"id": 1, "session": session, "verbose": 1, "method": "get", "params": [{"url": f"/dvmdb/adom/{selected_adom}/device"}]}, verify=False).json()
            devices = dev_res['result'][0].get('data', [])

            if not devices:
                print(f"\n{Colors.YELLOW}⚠ No devices in {selected_adom}.{Colors.END}")
                if adom_enabled:
                    selected_adom = None
                continue

            print(f"\n{Colors.BOLD}{Colors.HEADER}--- DEVICES IN {selected_adom.upper()} ---{Colors.END}")
            for i, dev in enumerate(devices):
                print(f"  [{Colors.CYAN}{i}{Colors.END}] {dev['name']:<30} ({dev.get('sn', 'N/A')})")

            choice = input(f"\n{Colors.CYAN}{Colors.BOLD}Choice ([all], [0,2], [0-5], [b]ack, [e]xit):{Colors.END} ").strip().lower()

            if choice in ('e', 'exit'):
                sys.exit(0)

            if choice == 'b':
                if adom_enabled:
                    selected_adom = None
                    clear_terminal()
                else:
                    print(f"\n{Colors.YELLOW}⚠ ADOMs are disabled.{Colors.END}")
                    time.sleep(1)
                continue

            try:
                if choice == 'all':
                    target_list = [{"name": d['name']} for d in devices]
                elif ',' in choice:
                    target_list = [{"name": devices[int(x.strip())]['name']} for x in choice.split(',')]
                elif '-' in choice:
                    start, end = map(int, choice.split('-'))
                    target_list = [{"name": devices[i]['name']} for i in range(start, end + 1)]
                else:
                    target_list = [{"name": devices[int(choice)]['name']}]
            except (ValueError, IndexError):
                print(f"{Colors.RED}Invalid choice.{Colors.END}")
                continue

            # --- EXECUTION ---
            print(f"\n{Colors.YELLOW}⚙ Triggering retrieval...{Colors.END}")
            exec_res = requests.post(base_url, json={"id": 1, "session": session, "method": "exec", "params": [{"url": "dvm/cmd/reload/dev-list", "data": {"adom": selected_adom, "flags": ["create_task", "nonblocking"], "reload-dev-member-list": target_list, "from": "dvm"}}]}, verify=False).json()

            task_id = exec_res['result'][0].get('data', {}).get('taskid')
            if task_id:
                while True:
                    status_res = requests.post(base_url, json={"id": 1, "session": session, "method": "get", "params": [{"url": f"/task/task/{task_id}"}]}, verify=False).json()
                    task_data = status_res['result'][0]['data']
                    percent = task_data.get('percent', 0)

                    clear_terminal()
                    print(f"{Colors.BLUE}{Colors.BOLD}⚙ RUNNING RETRIEVAL (TASK ID: {task_id}){Colors.END}\n")
                    for dev_entry in task_data.get('line', []):
                        color = Colors.GREEN if "finish" in dev_entry.get('detail', '').lower() else Colors.YELLOW
                        print(f"  {Colors.CYAN}→{Colors.END} {dev_entry.get('name', ''):<25} | {color}{dev_entry.get('detail', ''):<25}{Colors.END}")

                    bar = '█' * int(25 * percent / 100) + '░' * (25 - int(25 * percent / 100))
                    print(f"\n  Progress: |{Colors.BLUE}{bar}{Colors.END}| {percent}%")

                    if percent >= 100:
                        clear_terminal()
                        print_final_table(task_data)
                        break
                    time.sleep(1)

            action = input(f"Next Action: [1] Same ADOM [2] Change ADOM [3] Exit: ").strip()
            if action == "2":
                selected_adom = None if adom_enabled else 'root'
            elif action != "1":
                break

    finally:
        if 'session' in locals():
            requests.post(base_url, json={"id": 1, "session": session, "method": "exec", "params": [{"url": "/sys/logout"}]}, verify=False)
        print(f"\n{Colors.BLUE}✔ Session closed safely.{Colors.END}")

if __name__ == "__main__":
    main()