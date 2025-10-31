# CrowdStrike RTR Data Collector (Python)

This Python project interacts with the CrowdStrike Real-time Response (RTR) API to:

- Authenticate with the CrowdStrike API (OAuth2)
- Initialize a Real-time Response session with a target endpoint
- Run cloud-stored RTR scripts on the endpoint
- Poll for command status and collect script outputs
- Optionally upload parsed results to BloodHound Enterprise using HMAC-signed ingestion

## Features

- Authentication via CrowdStrike API credentials from `.env`
- RTR session lifecycle (init, run script, poll status)
- Parses stringified JSON from `stdout` when present
- Optional BloodHound Enterprise ingestion (HMAC-signed upload)
- Modular layout: `src/` contains client, utils, and RTR orchestration
- Logs and command outputs saved under `logs/` and `rtr-result/`

## Prerequisites

- Python 3.9+ (virtual environment recommended)
- CrowdStrike Falcon API credentials with Real-time Response read/write permissions
- (Optional) BloodHound Enterprise credentials if uploading results

## Repository Layout

```
crowdstrike-data-collector-python/
├── .env                    # Environment variables (credentials, options)
├── .gitignore
├── main.py                 # Entry-point (orchestrates scripts)
├── requirements.txt
├── logs/                   # Runtime logs (ignored by Git)
├── rtr-result/             # RTR command outputs (ignored by Git)
└── src/
    ├── crowdstrike_manager.py  # CrowdStrikeRTR and BloodhoundManager classes
    ├── rtr.py                  # Orchestration and polling helpers
    └── utils.py                # Logging, env parsing, directory helpers
```

## Setup

1. Create and activate a virtual environment (PowerShell example):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

2. Install dependencies:

```powershell
pip install -r requirements.txt
```

3. Create a `.env` file in the project root and set the required environment variables (example):

```text
# CrowdStrike API
CLIENT_ID="your_client_id"
CLIENT_SECRET="your_client_secret"
DEVICE_ID="target_device_id"

# Scripts to run (comma-separated names of cloud-stored scripts)
SCRIPT_FILE_NAMES="session-script.ps1,registry-key-script.ps1,localGroups-script.ps1"

# Optional BloodHound upload settings
UPLOAD_TO_BLOODHOUND=false
TOKEN_ID="your_bh_token_id"
TOKEN_KEY="your_bh_token_key"
TENANT_DOMAIN="https://your-bh.example/"

# Retry behavior
MAX_RETRIES=10
RETRY_DELAY=5
```

Notes:
- `SCRIPT_FILE_NAMES` is a comma-separated list of CloudFile script names to execute.
- `UPLOAD_TO_BLOODHOUND` true/false controls whether parsed results are uploaded.

## Usage

Run the main orchestration script from the project root:

```powershell
python main.py
```

What `main.py` does:
- Ensures `logs/` and `rtr-result/` directories exist
- Reads configuration from `.env` (script list, retry settings, upload toggles)
- For each script: sets up a per-script logger, obtains a CrowdStrike auth token, initializes an RTR session, runs the script, polls for command status and saves results
- Optionally uploads parsed results to BloodHound using the `BloodhoundManager`

## Environment variables (summary)

- CLIENT_ID: CrowdStrike API client id
- CLIENT_SECRET: CrowdStrike API client secret
- DEVICE_ID: Target device (host) ID to run RTR commands against
- SCRIPT_FILE_NAMES: Comma-separated list of cloud-stored script filenames to run
- UPLOAD_TO_BLOODHOUND: true/false — whether to upload results to BloodHound
- TOKEN_ID, TOKEN_KEY, TENANT_DOMAIN: BloodHound Enterprise HMAC credentials and URL
- MAX_RETRIES: Number of times to poll for command status
- RETRY_DELAY: Delay (seconds) between status poll attempts

## Error Handling

- Network and HTTP errors are logged. Fatal errors (like missing API credentials) will raise exceptions and stop the run for that script.
- When RTR `stdout` contains a stringified JSON payload, the client attempts to parse it and store the parsed object in the saved status.
- If BloodHound upload fails, the error is logged and will cause that upload to stop; collected results are still stored locally.

## Important Notes

- Make sure your CrowdStrike API client has the required RTR permissions (Read + Write).
- The target `DEVICE_ID` must be online and reachable.
- The cloud-stored script names you provide in `SCRIPT_FILE_NAMES` must exist in the Falcon UI.
- `logs/` and `rtr-result/` are already added to `.gitignore` to avoid committing runtime outputs.

## Development / Testing

- Use a dedicated test CrowdStrike API client and a non-production host when validating behavior.
- Add or adjust scripts in `SCRIPT_FILE_NAMES` to run different cloud-stored PowerShell scripts.

## Quick commands (PowerShell)

```powershell
# create venv and activate
python -m venv .venv
.\.venv\Scripts\Activate.ps1
# install
pip install -r requirements.txt
# run
python main.py
```

## Troubleshooting

- If authentication fails, verify `CLIENT_ID` / `CLIENT_SECRET` and network connectivity to `api.crowdstrike.com`.
- If sessions fail to initialize, ensure `DEVICE_ID` is correct and the host is online.
- Check `logs/<script>.log` for per-script debug details.

---

If you want, I can also:
- Add a short example `.env.example` file to the repo
- Add a simple smoke test (unit test) that validates env parsing and logger setup
- Run a quick local lint or static analysis pass

Tell me which next step you'd like. 
