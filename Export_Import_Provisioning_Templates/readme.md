# FortiManager Provisioning Templates Export/Import

Python utilities to automate **exporting and importing FortiManager provisioning templates** using the same internal `flatui` endpoints as the GUI.

These scripts are intended for lab/testing and admin automation, not as official Fortinet tools.

---

## Features

- Login to FortiManager using the GUI auth endpoint.
- Default to **root ADOM (OID 3)**, with an interactive prompt to switch ADOM.
- ADOM selection table (name, OID, version, type), with **Global ADOM (OID 10) hidden**.
- **Export script:**
  - Exports a predefined set of provisioning template categories from the selected ADOM.
  - Tracks the async export task until completion.
  - Downloads the raw export file exactly as the GUI does (no extra wrapping).
  - Prints a summary of the export to the console.
- **Import script:**
  - Lets you choose an export file by name from a local directory.
  - Uploads the file and triggers template import into the selected ADOM.
  - Polls the import task until FortiManager marks it finished.
  - Parses task details to surface errors (for example, version mismatches).

---

## Repository Contents

- `fmg_export_templates.py`  
  Export all provisioning templates from a chosen ADOM and save the export bundle locally.

- `fmg_import_templates.py`  
  Import a previously exported bundle into a chosen ADOM and show detailed task results.

You can keep both scripts in the same directory and share the same configuration pattern.

---

## Requirements

- Python 3.8+
- Network reachability to FortiManager over HTTPS
- Python packages:
  - `requests`
  - `urllib3`

Install dependencies:

```bash
pip install requests urllib3
