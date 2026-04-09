"""
FortiManager Devices' Configuration Retriever
Logs into FortiManager, lets you pick ADOM and device(s),
then Retrieves config.

by: Farhan Ahmed - www.farhan.ch
"""

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


def main():
    print(f"{Colors.BLUE}{Colors.BOLD}{'=' * 60}{Colors.END}")
    print(f"{Colors.BOLD}   FORTIMANAGER CONFIGURATION RETRIEVAL AUTOMATION{Colors.END}")
    print(f"{Colors.BLUE}{'=' * 60}{Colors.END}\n")

    # Updated prompt style: Removed arrow, used bold colon
    host = input(f"{Colors.CYAN}{Colors.BOLD}FMG IP/URL:{Colors.END} ").strip()
    user = input(f"{Colors.CYAN}{Colors.BOLD}Admin Username:{Colors.END} ").strip()
    pwd = input(f"{Colors.CYAN}{Colors.BOLD}Admin Password:{Colors.END} ")
    base_url = f"https://{host}/jsonrpc"

    # 1. Login
    login_payload = {
        "id": 1,
        "method": "exec",
        "params": [{"data": {"user": user, "passwd": pwd}, "url": "/sys/login/user"}]
    }

    try:
        login_res = requests.post(base_url, json=login_payload, verify=False).json()
        session = login_res.get("session")
    except Exception as e:
        print(f"\n{Colors.RED}✘ Connection failed: {e}{Colors.END}")
        return

    if not session:
        print(f"\n{Colors.RED}✘ Login failed. Check credentials.{Colors.END}")
        return

    print(f"\n{Colors.GREEN}✔ Session Established: {Colors.END}{Colors.BOLD}{session}{Colors.END}")

    selected_adom = None
    try:
        while True:
            if not selected_adom:
                print(f"\n{Colors.BOLD}{Colors.HEADER}--- AVAILABLE ADOMS ---{Colors.END}")
                adom_res = requests.post(base_url, json={
                    "id": 2, "session": session, "method": "get", "params": [{"url": "/dvmdb/adom/"}]
                }, verify=False).json()
                adoms = [a['name'] for a in adom_res['result'][0]['data']]
                for i, name in enumerate(adoms):
                    print(f"  [{Colors.CYAN}{i}{Colors.END}] {name}")

                idx = int(input(f"\n{Colors.BOLD}Select ADOM Index:{Colors.END} "))
                selected_adom = adoms[idx]

            # 2. Fetch and Check Devices
            print(f"\n{Colors.BOLD}{Colors.HEADER}--- DEVICES IN {selected_adom.upper()} ---{Colors.END}")
            dev_res = requests.post(base_url, json={
                "id": 1, "session": session, "verbose": 1, "method": "get",
                "params": [{"url": f"/dvmdb/adom/{selected_adom}/device"}]
            }, verify=False).json()

            devices = dev_res['result'][0].get('data', [])

            if not devices:
                print(f"{Colors.YELLOW}⚠ No devices found in this ADOM.{Colors.END}")
                choice = input(f"\nAction: (1) Select another ADOM (2) Exit: ")
                if choice == "1":
                    selected_adom = None
                    continue
                else:
                    break

            for i, dev in enumerate(devices):
                print(f"  [{Colors.CYAN}{i}{Colors.END}] {dev['name']:<30} ({dev.get('sn')})")

            # 3. Selection
            print(f"\n{Colors.BOLD}Target Selection:{Colors.END} [all], [0,2], or [0-5]")
            choice = input(f"{Colors.CYAN}{Colors.BOLD}Choice:{Colors.END} ").strip().lower()

            target_list = []
            if choice == 'all':
                target_list = [{"name": d['name']} for d in devices]
            elif '-' in choice:
                start, end = map(int, choice.split('-'))
                target_list = [{"name": devices[i]['name']} for i in range(start, end + 1)]
            else:
                indices = [int(i.strip()) for i in choice.split(',')]
                target_list = [{"name": devices[i]['name']} for i in indices]

            # 4. Task Execution
            print(f"\n{Colors.YELLOW}⚙ Triggering retrieval...{Colors.END}")
            exec_res = requests.post(base_url, json={
                "id": 1, "session": session, "method": "exec",
                "params": [{
                    "url": "dvm/cmd/reload/dev-list",
                    "data": {"adom": selected_adom, "flags": ["create_task", "nonblocking"],
                             "reload-dev-member-list": target_list, "from": "dvm"}
                }]
            }, verify=False).json()

            task_id = exec_res['result'][0].get('data', {}).get('taskid')
            if task_id:
                while True:
                    status_res = requests.post(base_url, json={
                        "id": 1, "session": session, "method": "get", "params": [{"url": f"/task/task/{task_id}"}]
                    }, verify=False).json()
                    task_data = status_res['result'][0]['data']
                    percent = task_data.get('percent', 0)

                    # Modern Block Progress Bar
                    bar_len = 20
                    filled = int(bar_len * percent / 100)
                    bar = '█' * filled + '░' * (bar_len - filled)
                    print(f"\r  Progress: |{Colors.BLUE}{bar}{Colors.END}| {percent}%", end="", flush=True)

                    if percent == 100:
                        print(f"\n\n{Colors.BOLD}--- TASK RESULTS ---{Colors.END}")
                        for entry in task_data.get('line', []):
                            status = f"{Colors.GREEN}PASS{Colors.END}" if entry.get(
                                'state') == 'done' else f"{Colors.RED}FAIL{Colors.END}"
                            print(f" {status} | {entry.get('name'):<25} | {entry.get('detail')}")
                        break
                    time.sleep(2)

            # 5. Next Steps
            print(f"\n{Colors.BOLD}Next Action:{Colors.END}")
            print(f" [1] Same ADOM  [2] Change ADOM  [3] Exit")
            move = input(f"{Colors.CYAN}{Colors.BOLD}Choice:{Colors.END} ").strip()

            if move == "1":
                continue
            elif move == "2":
                selected_adom = None
            else:
                break

    finally:
        requests.post(base_url,
                      json={"id": 1, "session": session, "method": "exec", "params": [{"url": "/sys/logout"}]},
                      verify=False)
        print(f"\n{Colors.BLUE}✔ Session closed safely. Goodbye!{Colors.END}")


if __name__ == "__main__":
    main()