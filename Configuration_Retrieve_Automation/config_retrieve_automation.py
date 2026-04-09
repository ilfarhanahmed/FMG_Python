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
        print(f"[!] Connection failed: {e}")
        return

    if not session:
        print("[!] Login failed.")
        return

    print(f"[*] Session Established: {session}")

    try:
        # 2. Get ADOMs
        adom_payload = {
            "id": 2, "session": session, "verbose": 1, "method": "get",
            "params": [{"url": "/dvmdb/adom/"}]
        }
        adom_res = requests.post(base_url, json=adom_payload, verify=False).json()
        adoms = [a['name'] for a in adom_res['result'][0]['data']]

        for i, name in enumerate(adoms): print(f"[{i}] {name}")
        adom_idx = int(input("\nSelect ADOM index: "))
        selected_adom = adoms[adom_idx]

        # 3. List Devices
        device_payload = {
            "id": 1, "session": session, "verbose": 1, "method": "get",
            "params": [{"url": f"/dvmdb/adom/{selected_adom}/device"}]
        }
        dev_res = requests.post(base_url, json=device_payload, verify=False).json()
        devices = dev_res['result'][0].get('data', [])

        for i, dev in enumerate(devices): print(f"[{i}] {dev['name']} ({dev.get('sn')})")

        # 4. Selection
        choice = input("\nSelection ('all', 0,2, or 0-5): ").strip().lower()
        target_list = []
        if choice == 'all':
            target_list = [{"name": d['name']} for d in devices]
        elif '-' in choice:
            start, end = map(int, choice.split('-'))
            target_list = [{"name": devices[i]['name']} for i in range(start, end + 1)]
        else:
            indices = map(int, choice.split(','))
            target_list = [{"name": devices[i]['name']} for i in indices]

        # 5. Execute Retrieval
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
            print(f"[*] Task ID: {task_id}")
            while True:
                task_payload = {
                    "id": 1, "session": session, "method": "get",
                    "params": [{"url": f"/task/task/{task_id}"}]
                }
                status_res = requests.post(base_url, json=task_payload, verify=False).json()
                task_data = status_res['result'][0]['data']
                percent = task_data.get('percent', 0)
                print(f"Progress: {percent}%", end='\r')

                if percent == 100:
                    print("\n\n--- TASK RESULTS PER DEVICE ---")
                    # Access the 'line' detail which contains specific device results
                    lines = task_data.get('line', [])
                    for entry in lines:
                        name = entry.get('name', 'Unknown Device')
                        state = entry.get('state', 'Unknown')
                        # Check for success/failure keywords in the detail
                        detail = entry.get('detail', 'No detail provided')

                        status_icon = "[OK]" if state == 'done' else "[FAILED]"
                        print(f"{status_icon} Device: {name}")
                        print(f"      Detail: {detail}\n")
                    break
                time.sleep(3)

    finally:
        requests.post(base_url,
                      json={"id": 1, "session": session, "method": "exec", "params": [{"url": "/sys/logout"}]},
                      verify=False)
        print("[*] Logged out.")


if __name__ == "__main__":
    main()