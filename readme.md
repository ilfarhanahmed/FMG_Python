# FortiManager Interface Configuration Reporter

This Python script automates the retrieval of network interface settings from devices managed by FortiManager. Using the Fortinet JSON-RPC API, it gathers hostnames, interface names, IP addresses, and DHCP statuses, exporting the results into a structured CSV file.

## Features

* **Session Management**: Handles JSON-RPC login and logout sequences, maintaining a persistent session ID for all calls.
* **Global Inventory**: Automatically iterates through all devices within a specified Administrative Domain (ADOM).
* **Config Extraction**: Pulls data directly from the Policy Manager (`pm`) configuration database for accurate reporting.
* **CSV Output**: Formats data for easy import into Excel, Power BI, or other auditing tools.

## Workflow

The script follows a standard API lifecycle:
1. **POST `/sys/login/user`**: Authenticates and retrieves a session token.
2. **GET `/dvmdb/adom/{ADOM}/device`**: Lists all managed devices.
3. **GET `/pm/config/device/{name}/...`**: Queries the specific Policy Manager configuration for each device interface.
4. **POST `/sys/logout`**: Gracefully terminates the session.

## Prerequisites

* **Python 3.6+**
* **Requests Library**: 
    ```bash
    pip install requests
    ```
* **FortiManager Access**: Ensure the API user has sufficient RPC permissions (Read-Only is enough for this script).

## Configuration

Update the following variables in the script header:

| Variable   | Description |
| :---       | :--- |
| `FMG_IP`   | The full URL to the JSON-RPC endpoint (e.g., `https://192.168.1.1/jsonrpc`). |
| `USERNAME` | Your FortiManager administrative username. |
| `PASSWORD` | Your FortiManager administrative password. |
| `ADOM`     | The Administrative Domain to query (default is `root`). |

## Usage

1. Clone or download the script.
2. Configure the credentials and IP settings.
3. Execute the script:
   ```bash
   python get_interfaces.py
