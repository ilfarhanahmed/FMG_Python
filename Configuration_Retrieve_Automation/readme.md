# FortiManager Retrieve Configuration Automation

A professional, interactive Python utility designed to automate the **Retrieve Config** process for FortiGate devices managed by FortiManager. This tool replaces manual Postman execution with a streamlined, terminal-based experience featuring real-time task monitoring.

- Postman Collection:
https://www.postman.com/ilfarhanahmed/workspace/fortimanager-public/collection/30322334-1995591c-fd59-4911-8289-48b06a694306

## Usage

1.  **Run the script**:
    ```bash
    python config_retrieve_automation.py
    ```

2.  **Authentication**: Enter your FortiManager IP, Admin Username, and Password when prompted (make sure to enable json-rpc for the admin user in FMG).
4.  **Select ADOM**: Choose the numerical index of the ADOM you wish to manage.
5.  **Select Devices**: 
    * Type `all` to retrieve config for every device in the list.
    * Type `0,2` for specific indices.
    * Type `0-5` for a range of devices.
6.  **Monitor**: Watch the live progress bar. Once finished, a summary table will display the status of each device.


## Features

* **Interactive ADOM Selection**: Automatically fetches and lists all available Administrative Domains (ADOMs) for the operator to choose from.
* **Intelligent Device Filtering**: Lists devices with their names and serial numbers for the selected ADOM.
* **Flexible Target Selection**: Supports selecting `all` devices, specific indices (e.g., `0,2`), or ranges (e.g., `0-5`).
* **Empty ADOM Handling**: Gracefully detects when an ADOM has no devices and allows the user to jump back to the selection menu.
* **Real-time Progress Monitoring**: Displays a modern Unicode block progress bar tracking the FortiManager Task ID until 100% completion.
* **Detailed Results Summary**: Provides a PASS/FAIL breakdown per device with specific FortiManager error details (e.g., `unregoffline`).
* **Persistent Session**: Stay logged in to perform multiple retrievals across different ADOMs without re-authenticating.

## Requirements

* **Python 3.8+**
* **`requests` library**: Used for JSON-RPC API communication.
* **Network Access**: Connectivity to your FortiManager IP over HTTPS (Port 443).

## Installation

1.  **Clone the repository**:
    ```bash
    git clone [https://github.com/USERNAME/REPOSITORY-NAME.git](https://github.com/USERNAME/REPOSITORY-NAME.git)
    cd REPOSITORY-NAME
    ```

2.  **Install dependencies**:
    ```bash
    pip install requests
    ```

## Technical Details

This tool utilizes the **FortiManager JSON-RPC API** as defined in the automation collection. Key API methods implemented:
* `exec /sys/login/user`: For session establishment.
* `get /dvmdb/adom/`: To retrieve the list of administrative domains.
* `exec dvm/cmd/reload/dev-list`: To trigger the non-blocking configuration retrieval task.
* `get /task/task/{id}`: To poll for real-time execution percentages and device logs.

## Security Note

This script is configured with `verify=False` to accommodate internal environments with self-signed certificates. In production environments, it is recommended to use valid CA-signed certificates and enable SSL verification.
