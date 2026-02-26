
import requests
import json
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── CONFIG ───────────────────────────────────────────────────────────────────
FMG_HOST = "https://<FMG_IP>"
ADMIN    = "<admin>"
PASSWORD = "<admin_pass>"
# ──────────────────────────────────────────────────────────────────────────────

session = requests.Session()
session.verify = False
JSONRPC = f"{FMG_HOST}/jsonrpc"


def fmg_request(payload: dict) -> dict:
    r = session.post(JSONRPC, json=payload)
    r.raise_for_status()
    return r.json()


# 1. Login
def login() -> str:
    resp = fmg_request({
        "id": 1,
        "method": "exec",
        "params": [{"url": "/sys/login/user", "data": {"user": ADMIN, "passwd": PASSWORD}}]
    })

    # Check for login failure before accessing session
    status = resp.get("result", [{}])[0].get("status", {})
    code   = status.get("code", -1)
    msg    = status.get("message", "Unknown error")

    if code != 0:
        raise Exception(f"❌ FMG Login failed (code {code}): {msg}")

    token = resp["session"]
    print("✅ Logged in.")
    return token



# 2. List all managed devices
def list_devices(token: str) -> list[str]:
    resp = fmg_request({
        "id": 1,
        "method": "get",
        "params": [{"url": "/dvmdb/device"}],
        "session": token,
        "verbose": 1
    })
    devices = resp["result"][0]["data"]
    targets = [f"device/{d['name']}" for d in devices]
    print(f"📋 Found {len(targets)} devices.")
    return targets


# 3. Bulk fetch system/global from all devices at once
def fetch_sso_status(token: str, targets: list[str]) -> list[dict]:
    resp = fmg_request({
        "id": 1,
        "method": "exec",
        "params": [{
            "url": "sys/proxy/json",
            "data": {
                "target": targets,
                "action": "get",
                "resource": "/api/v2/cmdb/system/global"
            }
        }],
        "session": token
    })

    results = []
    for entry in resp["result"][0]["data"]:
        device_name = entry["target"].replace("device/", "")
        try:
            sso_status = entry["response"]["results"]["admin-forticloud-sso-login"]
        except (KeyError, TypeError):
            sso_status = "ERROR"
        results.append({"device": device_name, "sso_status": sso_status})

    return results


# 4. Logout
def logout(token: str):
    fmg_request({
        "id": 1,
        "method": "exec",
        "params": [{"url": "/sys/logout"}],
        "session": token
    })
    print("👋 Logged out.")


# 5. Print report
def print_report(results: list[dict]):
    print(f"\n{'─'*47}")
    print(f"{'Device Name':<25} {'admin-forticloud-sso'}")
    print(f"{'─'*47}")
    for row in results:
        status = row["sso_status"]
        icon = "🟢" if status == "enable" else "🔴" if status == "disable" else "⚠️"
        print(f"{row['device']:<25} {icon} {status}")
    print(f"{'─'*47}\n")


# ── MAIN ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    token   = login()
    targets = list_devices(token)
    results = fetch_sso_status(token, targets)
    logout(token)
    print_report(results)

    # Optional: export to JSON
    with open("sso_report.json", "w") as f:
        json.dump(results, f, indent=2)
    print("💾 Report saved to sso_report.json")
