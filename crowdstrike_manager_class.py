import requests
import json
import time
import os
from dotenv import load_dotenv

# Load environment variables from .env file (can also be done in main.py)
# It's often good to load them where they are first needed, or in a central config.
# For simplicity, keeping it here for the class to directly access them.
load_dotenv()


class CrowdStrikeRTR:
    def __init__(self):
        # --- CrowdStrike API Credentials ---
        self.client_id = os.getenv("CLIENT_ID")
        self.client_secret = os.getenv("CLIENT_SECRET")

        if not self.client_id or not self.client_secret:
            raise ValueError(
                "CLIENT_ID and CLIENT_SECRET must be set in the .env file."
            )

        # --- API Endpoints ---
        self.base_url = "https://api.crowdstrike.com"
        self.auth_token_url = f"{self.base_url}/oauth2/token"
        self.rtr_session_url = (
            f"{self.base_url}/real-time-response/entities/sessions/v1"
        )
        self.rtr_admin_command_url = (
            f"{self.base_url}/real-time-response/entities/admin-command/v1"
        )

        # --- Instance Variables for Session Management ---
        self.access_token = None
        self.device_id = os.getenv("DEVICE_ID")
        self.session_id = None
        self.cloud_request_id = None

        if not self.device_id:
            print(
                "Warning: DEVICE_ID not found in .env. Please set it or provide it programmatically."
            )

    def _get_headers(self, content_type="application/json", include_auth=True):
        """
        Helper to construct HTTP headers.
        Args:
            content_type (str): The Content-Type header value.
            include_auth (bool): Whether to include the Authorization header.
        Returns:
            dict: Dictionary of headers.
        """
        headers = {
            "accept": "application/json",
            "Content-Type": content_type,
        }
        if include_auth and self.access_token:
            headers["authorization"] = f"Bearer {self.access_token}"
        return headers

    def _make_api_call(
        self, method, url, headers, params=None, json_data=None, data=None
    ):
        """
        Generic method to make API calls and handle common errors.
        Args:
            method (str): HTTP method (e.g., "GET", "POST").
            url (str): The API endpoint URL.
            headers (dict): HTTP headers for the request.
            params (dict, optional): URL parameters.
            json_data (dict, optional): JSON payload for the request body.
            data (dict, optional): Form-urlencoded data for the request body.
        Returns:
            dict: JSON response if successful, None otherwise.
        """
        response = None
        try:
            if method.upper() == "POST":
                response = requests.post(
                    url, headers=headers, params=params, json=json_data, data=data
                )
            elif method.upper() == "GET":
                response = requests.get(url, headers=headers, params=params)
            # Add more methods (PUT, DELETE) if needed

            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
            return response.json()
        except requests.exceptions.HTTPError as http_err:
            print(
                f"HTTP error occurred: {http_err} - Status Code: {response.status_code}"
            )
            if response is not None:
                print(f"Response content: {response.text}")
        except requests.exceptions.ConnectionError as conn_err:
            print(
                f"Connection error occurred: {conn_err} - Check network connectivity."
            )
        except requests.exceptions.Timeout as timeout_err:
            print(f"Timeout error occurred: {timeout_err} - The request took too long.")
        except requests.exceptions.RequestException as req_err:
            print(f"An unexpected request error occurred: {req_err}")
            if response is not None:
                print(f"Response content: {response.text}")
        except json.JSONDecodeError as json_err:
            print(f"JSON decoding error: {json_err} - Response text: {response.text}")
        return None

    def get_auth_token(self):
        """
        Obtains an authentication token from the CrowdStrike API using _make_api_call.
        """
        headers = self._get_headers(
            content_type="application/x-www-form-urlencoded", include_auth=False
        )
        data = {"client_id": self.client_id, "client_secret": self.client_secret}

        print("Attempting to get authentication token...")
        token_info = self._make_api_call(
            "POST", self.auth_token_url, headers=headers, data=data
        )

        if token_info:
            self.access_token = token_info.get("access_token")
            if self.access_token:
                print("Authentication token obtained successfully.")
                return True
            else:
                print("Failed to get access token from response.")
        return False

    def initialize_rtr_session(self, device_id=None):
        """
        Initializes a new Real-time Response session with the cloud using _make_api_call.
        """
        target_device_id = device_id if device_id else self.device_id
        if not target_device_id:
            print("Device ID not provided. Cannot initialize RTR session.")
            return False

        headers = self._get_headers()
        params = {"timeout": 30, "timeout_duration": "30s"}
        payload = {"device_id": target_device_id, "queue_offline": False}

        print(
            f"\nAttempting to initialize RTR session for device: {target_device_id}..."
        )
        session_info = self._make_api_call(
            "POST",
            self.rtr_session_url,
            headers=headers,
            params=params,
            json_data=payload,
        )

        if session_info:
            print("RTR Session Initialization Response:")
            print(json.dumps(session_info, indent=2))
            resources = session_info.get("resources")
            if resources and len(resources) > 0:
                self.session_id = resources[0].get("session_id")
                if self.session_id:
                    print(f"RTR Session ID: {self.session_id}")
                    return True
            print("Failed to get session_id from RTR session initialization response.")
        return False

    def run_rtr_script(
        self, script_name="test-omkar.ps1", device_id=None, session_id=None
    ):
        """
        Runs an RTR script on a host using _make_api_call.
        """
        target_device_id = device_id if device_id else self.device_id
        target_session_id = session_id if session_id else self.session_id

        if not target_device_id or not target_session_id:
            print("Device ID or Session ID not available. Cannot run RTR script.")
            return False

        headers = self._get_headers()
        payload = {
            "base_command": "runscript",
            "command_string": f'runscript -CloudFile="{script_name}"',
            "device_id": target_device_id,
            "id": 0,
            "persist": True,
            "session_id": target_session_id,
        }

        print(
            f"\nAttempting to run RTR script '{script_name}' for session: {target_session_id} on device: {target_device_id}..."
        )
        command_response = self._make_api_call(
            "POST", self.rtr_admin_command_url, headers=headers, json_data=payload
        )

        if command_response:
            print("Run RTR Script Response:")
            print(json.dumps(command_response, indent=2))
            resources = command_response.get("resources")
            if resources and len(resources) > 0:
                self.cloud_request_id = resources[0].get("cloud_request_id")
                if self.cloud_request_id:
                    print(f"Cloud Request ID for command: {self.cloud_request_id}")
                    return True
            print("Failed to get cloud_request_id from run script response.")
        return False

    def get_rtr_command_status(self, cloud_request_id=None, sequence_id=0):
        """
        Gets the status of a single executed RTR administrator command using _make_api_call.
        """
        target_cloud_request_id = (
            cloud_request_id if cloud_request_id else self.cloud_request_id
        )

        if not target_cloud_request_id:
            print("Cloud Request ID not available. Cannot get command status.")
            return None

        headers = self._get_headers()
        params = {
            "cloud_request_id": target_cloud_request_id,
            "sequence_id": sequence_id,
        }

        print(
            f"\nAttempting to get status for command with Cloud Request ID: {target_cloud_request_id}..."
        )
        status_response = self._make_api_call(
            "GET", self.rtr_admin_command_url, headers=headers, params=params
        )

        if status_response:
            print("RTR Command Status Response:")
            print(json.dumps(status_response, indent=2))
        return status_response

    # Example of a public method to get headers (though usually _get_headers is sufficient)
    # You generally don't want to expose internal helper methods like _get_headers directly
    # unless there's a specific need for consumers to build headers for custom calls.
    # If a user wants to make a raw API call, they might need this.
    def get_configured_headers(self, content_type="application/json"):
        """
        Public method to expose configured headers with current access token.
        Useful if you want to make raw requests outside the class using its auth.
        """
        return self._get_headers(content_type=content_type, include_auth=True)

    # Example of a public method to make an API call (if you want to expose raw API access)
    def make_custom_api_call(
        self,
        method,
        url_path,
        params=None,
        json_data=None,
        data=None,
        content_type="application/json",
    ):
        """
        Public method to make a custom API call to any CrowdStrike endpoint.
        Requires authentication.
        Args:
            method (str): HTTP method (e.g., "GET", "POST").
            url_path (str): The path to the API endpoint (e.g., "/some/other/endpoint/v1").
            params (dict, optional): URL parameters.
            json_data (dict, optional): JSON payload for the request body.
            data (dict, optional): Form-urlencoded data for the request body.
            content_type (str): The Content-Type header value.
        Returns:
            dict: JSON response if successful, None otherwise.
        """
        if not self.access_token:
            print("Access token not available. Please authenticate first.")
            return None

        full_url = f"{self.base_url}{url_path}"
        headers = self._get_headers(content_type=content_type, include_auth=True)
        print(f"Making custom API call to {full_url} with method {method}")
        return self._make_api_call(
            method, full_url, headers, params=params, json_data=json_data, data=data
        )
