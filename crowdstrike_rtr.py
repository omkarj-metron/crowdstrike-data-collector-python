import requests
import base64
import json
import time

# --- CrowdStrike API Credentials (REPLACE WITH YOURS) ---
CLIENT_ID = "04b1dfc70dd745458f0d433e9cfb86c2"
CLIENT_SECRET = "XI2xast9JBEoNdye8YM4QT03k5npRWKVA71zHiw6"

# --- API Endpoints ---
BASE_URL = "https://api.crowdstrike.com"
AUTH_TOKEN_URL = f"{BASE_URL}/oauth2/token"
RTR_SESSION_URL = f"{BASE_URL}/real-time-response/entities/sessions/v1"
RTR_ADMIN_COMMAND_URL = f"{BASE_URL}/real-time-response/entities/admin-command/v1"

# --- Device ID and Session ID (Example values - REPLACE with actual values if needed) ---
# For a real scenario, you would typically get the device_id from other CrowdStrike APIs
# or your inventory. The session_id is obtained from the RTR session initialization.
DEVICE_ID = "1bd81f8b64bd41e291ffba2337ba80ba"
SESSION_ID = "fc0ce3cd-c337-4c15-b201-0112e2e7c601"  # This will be updated after session creation
CLOUD_REQUEST_ID = ""  # This will be updated after running the admin command


def get_auth_token(client_id, client_secret):
    """
    Obtains an authentication token from the CrowdStrike API.
    """
    headers = {
        "accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data = {"client_id": client_id, "client_secret": client_secret}

    print("Attempting to get authentication token...")
    try:
        response = requests.post(AUTH_TOKEN_URL, headers=headers, data=data)
        response.raise_for_status()  # Raise an exception for HTTP errors (4xx or 5xx)
        token_info = response.json()
        access_token = token_info.get("access_token")
        if access_token:
            print("Authentication token obtained successfully.")
            return access_token
        else:
            print("Failed to get access token from response.")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Error getting authentication token: {e}")
        print(f"Response content: {response.text}")
        return None


def initialize_rtr_session(access_token, device_id):
    """
    Initializes a new Real-time Response session with the cloud.
    """
    headers = {
        "accept": "application/json",
        "authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    params = {"timeout": 30, "timeout_duration": "30s"}
    payload = {"device_id": device_id, "queue_offline": False}

    print(f"\nAttempting to initialize RTR session for device: {device_id}...")
    try:
        response = requests.post(
            RTR_SESSION_URL, headers=headers, params=params, json=payload
        )
        response.raise_for_status()
        session_info = response.json()
        print("RTR Session Initialization Response:")
        print(json.dumps(session_info, indent=2))

        # Extract session_id from the response
        resources = session_info.get("resources")
        if resources and len(resources) > 0:
            session_id = resources[0].get("session_id")
            if session_id:
                print(f"RTR Session ID: {session_id}")
                return session_id
        print("Failed to get session_id from RTR session initialization response.")
        return None
    except requests.exceptions.RequestException as e:
        print(f"Error initializing RTR session: {e}")
        print(f"Response content: {response.text}")
        return None


def run_rtr_script(access_token, device_id, session_id):
    """
    Runs an RTR script on a host.
    """
    headers = {
        "accept": "application/json",
        "authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    payload = {
        "base_command": "runscript",
        "command_string": 'runscript -CloudFile="test-omkar.ps1"',
        "device_id": device_id,
        "id": 0,
        "persist": True,
        "session_id": session_id,
    }

    print(
        f"\nAttempting to run RTR script for session: {session_id} on device: {device_id}..."
    )
    try:
        response = requests.post(RTR_ADMIN_COMMAND_URL, headers=headers, json=payload)
        response.raise_for_status()
        command_response = response.json()
        print("Run RTR Script Response:")
        print(json.dumps(command_response, indent=2))

        # Extract cloud_request_id for status checking
        resources = command_response.get("resources")
        if resources and len(resources) > 0:
            cloud_request_id = resources[0].get("cloud_request_id")
            if cloud_request_id:
                print(f"Cloud Request ID for command: {cloud_request_id}")
                return cloud_request_id
        print("Failed to get cloud_request_id from run script response.")
        return None
    except requests.exceptions.RequestException as e:
        print(f"Error running RTR script: {e}")
        print(f"Response content: {response.text}")
        return None


def get_rtr_command_status(access_token, cloud_request_id, sequence_id=0):
    """
    Gets the status of a single executed RTR administrator command.
    """
    headers = {"accept": "application/json", "authorization": f"Bearer {access_token}"}
    params = {"cloud_request_id": cloud_request_id, "sequence_id": sequence_id}

    print(
        f"\nAttempting to get status for command with Cloud Request ID: {cloud_request_id}..."
    )
    try:
        response = requests.get(RTR_ADMIN_COMMAND_URL, headers=headers, params=params)
        response.raise_for_status()
        status_response = response.json()
        print("RTR Command Status Response:")
        print(json.dumps(status_response, indent=2))
        return status_response
    except requests.exceptions.RequestException as e:
        print(f"Error getting RTR command status: {e}")
        print(f"Response content: {response.text}")
        return None


def main():
    # 1. Get Authentication Token
    auth_token = get_auth_token(CLIENT_ID, CLIENT_SECRET)

    if auth_token:
        # 2. Initialize RTR Session
        session_id = initialize_rtr_session(auth_token, DEVICE_ID)

        if session_id:
            # Update the global SESSION_ID for clarity, though it's passed directly
            globals()["SESSION_ID"] = session_id

            # 3. Run the RTR Script
            cloud_request_id = run_rtr_script(auth_token, DEVICE_ID, SESSION_ID)

            if cloud_request_id:
                # Update the global CLOUD_REQUEST_ID
                globals()["CLOUD_REQUEST_ID"] = cloud_request_id
                time.sleep(5)

                # 4. Get Status of the executed RTR command
                get_rtr_command_status(auth_token, CLOUD_REQUEST_ID)
            else:
                print("Failed to get cloud_request_id. Cannot get command status.")
        else:
            print("Failed to initialize RTR session. Skipping further API calls.")
    else:
        print("Failed to get authentication token. Exiting.")


if __name__ == "__main__":
    main()
