import requests
import json
import time
import sys

# Suppress insecure request warnings
requests.packages.urllib3.disable_warnings()


def main():
    print("--- FortiManager Configuration Retrieval Automation ---")

    host = input("FMG IP/URL: ").strip()
    user = input("Admin Username: ").strip()
    pwd = input("Admin Password: ")
    base_url = f"https://{host}/jsonrpc"

    # 1. Initial Login
    login_payload = {
        "id": 1,
        "method": "exec",
        "params": [{"data": {"user": user, "passwd": pwd}, "url": "/sys/login/user"}]
    }

    try:
        login_res = requests.post(base_url, json=login_payload, verify=False).json()
        session = login_res.get("session")
    except Exception as e:
        print(f"[!] Connection failed: {e}")
        return

    if not session:
        print("[!] Login failed. Check credentials.")
        return

    print(f"[*] Session Established: {session}")

    selected_adom = None

    try:
        while True:
            # 2. ADOM Selection (Only if not already selected or if user wants to change)
            if not selected_adom:
                adom_payload = {
                    "id": 2, "session": session, "verbose": 1, "method": "get",
                    "params": [{"url": "/dvmdb/adom/"}]
                }
                adom_res = requests.post(base_url, json=adom_payload, verify=False).json()
                adoms = [a['name'] for a in adom_res['result'][0]['data']]

                print("\nAvailable ADOMs:")
                for i, name in enumerate(adoms): print(f"[{i}] {name}")

                adom_idx = int(input("\nSelect ADOM index: "))
                selected_adom = adoms[adom_idx]

            # 3. Device List
            device_payload = {
                "id": 1, "session": session, "verbose": 1, "method": "get",
                "params": [{"url": f"/dvmdb/adom/{selected_adom}/device"}]
            }
            print(f"\n[*] Fetching devices in {selected_adom}...")
            dev_res = requests.post(base_url, json=device_payload, verify=False).json()
            devices = dev_res['result'][0].get('data', [])

            if not devices:
                print("[!] No devices found.")
            else:
                for i, dev in enumerate(devices):
                    print(f"[{i}] {dev['name']} ({dev.get('sn')})")

                # 4. Target Selection
                print("\nSelection: 'all', comma-separated (0,2), or range (0-5)")
                choice = input("Your selection: ").strip().lower()

                target_list = []
                try:
                    if choice == 'all':
                        target_list = [{"name": d['name']} for d in devices]
                    elif '-' in choice:
                        start, end = map(int, choice.split('-'))
                        target_list = [{"name": devices[i]['name']} for i in range(start, end + 1)]
                    else:
                        indices = map(int, choice.split(','))
                        target_list = [{"name": devices[i]['name']} for i in indices]
                except (ValueError, IndexError):
                    print("[!] Invalid selection.")
                    continue

                # 5. Execute Task
                print(f"[*] Triggering retrieval for {len(target_list)} devices...")
                retrieve_payload = {
                    "id": 1, "session": session, "method": "exec",
                    "params": [{
                        "url": "dvm/cmd/reload/dev-list",
                        "data": {
                            "adom": selected_adom,
                            "flags": ["create_task", "nonblocking"],
                            "reload-dev-member-list": target_list,
                            "from": "dvm"
                        }
                    }]
                }

                exec_res = requests.post(base_url, json=retrieve_payload, verify=False).json()
                task_id = exec_res['result'][0].get('data', {}).get('taskid')

                if task_id:
                    print(f"[*] Task {task_id} progress: ", end="")
                    while True:
                        status_res = requests.post(base_url, json={"id": 1, "session": session, "method": "get",
                                                                   "params": [{"url": f"/task/task/{task_id}"}]},
                                                   verify=False).json()
                        task_data = status_res['result'][0]['data']
                        percent = task_data.get('percent', 0)
                        print(f"{percent}% ", end="", flush=True)

                        if percent == 100:
                            print("\n\n--- RESULTS ---")
                            for entry in task_data.get('line', []):
                                status = "[OK]" if entry.get('state') == 'done' else "[FAILED]"
                                print(f"{status} {entry.get('name')}: {entry.get('detail')}")
                            break
                        time.sleep(3)

            # 6. Post-Retrieval Prompt
            print("\n" + "=" * 30)
            print("What would you like to do next?")
            print("[1] Retrieve more from SAME ADOM")
            print("[2] Retrieve from DIFFERENT ADOM")
            print("[3] Exit and Logout")

            next_move = input("\nChoice (1-3): ").strip()

            if next_move == "1":
                continue  # Stays in loop, keeps current selected_adom
            elif next_move == "2":
                selected_adom = None  # Resets ADOM, loop will prompt for list again
            else:
                break  # Breaks loop to logout

    finally:
        # Final Logout
        requests.post(base_url,
                      json={"id": 1, "session": session, "method": "exec", "params": [{"url": "/sys/logout"}]},
                      verify=False)
        print("\n[*] Session closed. Goodbye.")


if __name__ == "__main__":
    main()