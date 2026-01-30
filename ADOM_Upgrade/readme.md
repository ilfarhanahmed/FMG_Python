# FortiManager ADOM Sequential Upgrader

An advanced Python automation tool designed to safely manage Administrative Domain (ADOM) upgrades on FortiManager via JSON-RPC. 



## 🧠 Logic & Workflow

1. **Authentication**: Establishes a secure session and identifies the FMG's own firmware version as the ultimate target.
2. **Product Filtering**: Uses **Bitmask Integers** (Value `1` for FortiOS) to isolate FortiGate ADOMs while skipping other products (Analyzer, Mail, etc.).
3. **Sequential Pathing (n+1)**: Calculates the next logical version (e.g., 7.2 → 7.4) to ensure database schema stability.
4. **Task Polling**: Monitors the FMG Task Manager in real-time until each ADOM reaches 100%.

## 🛡️ Safety Features

* **`UPGRADE_IGNORE` List**: Hardcoded protection for system ADOMs (`rootp`, `others`, `Syslog`) and specialized products.
* **Blocking Execution**: Upgrades are processed one-at-a-time to prevent CPU exhaustion on the FortiManager.
* **Automated Logout**: Ensures API sessions are cleared even if the script terminates unexpectedly.



## 🛠️ Configuration

Clone the repository and update the placeholders in `adom_upgrade.py`:

```python
HOST = "XXX.XXX.XXX.XXX" # FMG IP
USER = "admin"
PASS = "your_password"

On FMG admin user, make sure to have JSON-RPC permission set to READ.
