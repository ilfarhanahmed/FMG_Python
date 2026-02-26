# 🔐 FortiCloud SSO Login Checker

A Python script that queries **FortiManager** to audit the `admin-forticloud-sso-login`
setting across all managed FortiGate devices in a single bulk API call.

---

## 📋 Overview

Instead of checking each device manually through the GUI, this script connects to
FortiManager via the JSON-RPC API, retrieves all managed devices, and fetches the
`admin-forticloud-sso-login` value from every FortiGate simultaneously using the
`sys/proxy/json` proxy endpoint.

Results are printed to the console in a formatted report and saved as `sso_report.json`.

---

## 🖥️ Sample Output

```
🔐 Connecting to FortiManager...
   ✅ Authenticated successfully as 'admin'

📡 Retrieving managed device list...
   📋 3 device(s) found: FGT-VM, FGT-60E, FortiGate-40F

🔍 Fetching FortiCloud SSO login status from all devices...

👋 Session closed.

══════════════════════════════════════════════
   FortiCloud SSO Login Status Report
   Generated: 2026-02-25 17:36:00
══════════════════════════════════════════════
   Device Name        Status
──────────────────────────────────────────────
   FGT-VM             🔴  Disabled
   FGT-60E            🔴  Disabled
   FortiGate-40F      🔴  Disabled
──────────────────────────────────────────────

   📊 Summary:  0 enabled  |  3 disabled  |  0 error(s)
   📁 Total devices checked: 3
══════════════════════════════════════════════

💾 Full report saved to sso_report.json
```

---

## ⚙️ Requirements

- Python 3.10+
- `requests` library

Install dependencies:

```bash
pip install requests
```

---

## 🚀 Usage

**1. Clone the repository:**

```bash
git clone https://github.com/<your-username>/foricloud-sso-login-check.git
cd foricloud-sso-login-check
```

**2. Edit the config block at the top of the script:**

```python
FMG_HOST = "https://<FMG_IP>"
ADMIN    = "<admin_user>"
PASSWORD = "<admin_pass>"
```

**3. Run the script:**

```bash
python foricloud_sso_login_check.py
```

---

## 📁 Output

| File | Description |
|---|---|
| `sso_report.json` | Full results in JSON format, one entry per device |

**Example `sso_report.json`:**

```json
[
  { "device": "FGT-VM",        "sso_status": "disable" },
  { "device": "FGT-60E",       "sso_status": "disable" },
  { "device": "FortiGate-40F", "sso_status": "disable" }
]
```

---

## 🔑 FortiManager API Requirements

- The admin account must be a **Local** type (not RADIUS/LDAP/PKI)
- The account must have at least **read access** to device management
- It is recommended to create a **dedicated API admin** in FMG:

```
System > Administrators > Create New
  - Type:          Local
  - Admin Profile: Standard_User (read-only) or Super_User
  - Trusted Hosts: Set to your machine's IP for security
```

---

## 🛠️ How It Works

```
1. Login          →  POST /jsonrpc  (sys/login/user)
2. List Devices   →  POST /jsonrpc  (dvmdb/device)
3. Bulk Fetch     →  POST /jsonrpc  (sys/proxy/json → /api/v2/cmdb/system/global)
4. Logout         →  POST /jsonrpc  (sys/logout)
```

The key efficiency gain is in step 3 — all devices are passed as an array to
`sys/proxy/json`, so FortiManager fans out the request internally and returns
all results in a **single API response** instead of one call per device.

---

## ⚠️ Disclaimer

SSL verification is disabled by default (`verify=False`) to support self-signed
certificates common in lab environments. For production use, replace with your
FortiManager's CA certificate:

```python
session.verify = "/path/to/ca-cert.pem"
```

---

## 📄 License

MIT License — free to use, modify, and distribute.
