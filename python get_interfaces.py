import requests
import csv
import json
import urllib3

urllib3.disable_warnings()

FMG_IP = "https://<FMG_IP>/jsonrpc"
USERNAME = "<ADMIN>"
PASSWORD = "<PASSWORD>"
ADOM = "root"

session = requests.Session()
session.verify = False

# --- UPDATED FUNCTION TO ACCEPT SESSION_ID ---
def rpc(method, params, session_id=None):
    payload = {
        "id": 1,
        "method": method,
        "params": params
    }
    # Explicitly add the session key to the JSON body
    if session_id:
        payload["session"] = session_id
        
    r = session.post(FMG_IP, json=payload)
    return r.json()

# ---- LOGIN ----
login_payload = {
    "url": "/sys/login/user",
    "data": {
        "user": USERNAME,
        "passwd": PASSWORD
    }
}

resp = rpc("exec", [login_payload])

# Extract the session key from the response
try:
    SESSION_ID = resp["session"]
    print(f"Logged in. Session ID: {SESSION_ID[:20]}...") 
except KeyError:
    print(json.dumps(resp, indent=2))
    raise SystemExit("Login failed: Session key not found in response.")



# ---- GET DEVICES (Passing the SESSION_ID) ----
devices = rpc("get", [{"url": f"/dvmdb/adom/{ADOM}/device"}], session_id=SESSION_ID)

res = devices["result"][0]
if "data" in res:
    dev_list = res["data"]
elif "response" in res and "data" in res["response"]:
    dev_list = res["response"]["data"]
else:
    print(json.dumps(devices, indent=2))
    raise SystemExit("Could not find device list in response")

rows = []

# ---- LOOP DEVICES ----
for d in dev_list:
    name = d["name"]

    # Passing the SESSION_ID here as well
    iface_resp = rpc("get", [{
        "url": f"/pm/config/device/{name}/global/system/interface"
    }], session_id=SESSION_ID)

    ires = iface_resp["result"][0]

    if "data" in ires:
        ifaces = ires["data"]
    elif "response" in ires and "data" in ires["response"]:
        ifaces = ires["response"]["data"]
    else:
        ifaces = []

    for i in ifaces:
        iface = i.get("name","")
        ip = i.get("ip","")
        mode = i.get("mode","static")
        dhcp = "enabled" if mode == "dhcp" else "disabled"

        rows.append([name, iface, ip, dhcp])

    print(f"Pulled {name}")

# ---- WRITE CSV ----
with open("interfaces.csv","w",newline="") as f:
    w = csv.writer(f)
    w.writerow(["Hostname","Interface","IP","DHCP"])
    w.writerows(rows)

# ---- LOGOUT (Best Practice) ----
rpc("exec", [{"url": "/sys/logout"}], session_id=SESSION_ID)

print("interfaces.csv created and logged out.")
