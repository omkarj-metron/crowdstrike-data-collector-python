import requests
import json
import time
import os
import logging
import hmac
import hashlib
import base64
from dotenv import load_dotenv
from urllib.parse import urljoin, urlparse

# Load environment variables from .env file
load_dotenv()


class CrowdStrikeRTR:
    def __init__(self, logger: logging.Logger = None):
        # logger is optional; fall back to basic logging or print
        self.logger = logger or logging.getLogger("CrowdStrikeRTR")
        if not logger:
            # configure basic logging for convenience
            logging.basicConfig(level=logging.INFO)

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
        self.rtr_session_url = f"{self.base_url}/real-time-response/entities/sessions/v1"
        self.rtr_admin_command_url = f"{self.base_url}/real-time-response/entities/admin-command/v1"

        # --- Instance Variables for Session Management ---
        self.access_token = None
        self.device_id = os.getenv("DEVICE_ID")
        self.session_id = None
        self.cloud_request_id = None

        if not self.device_id:
            self.logger.warning("DEVICE_ID not found in .env. Please set it or provide it programmatically.")

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
            # Some endpoints (like BHE chunk upload) may return plain text. Try JSON, fallback to text.
            try:
                return response.json()
            except ValueError:
                return {"_raw_text": response.text}
        except requests.exceptions.HTTPError as http_err:
            self.logger.error(f"HTTP error occurred: {http_err} - Status Code: {getattr(response, 'status_code', 'N/A')}")
            if response is not None:
                self.logger.debug(f"Response content: {response.text}")
        except requests.exceptions.ConnectionError as conn_err:
            self.logger.error(f"Connection error occurred: {conn_err} - Check network connectivity.")
        except requests.exceptions.Timeout as timeout_err:
            self.logger.error(f"Timeout error occurred: {timeout_err} - The request took too long.")
        except requests.exceptions.RequestException as req_err:
            self.logger.error(f"An unexpected request error occurred: {req_err}")
            if response is not None:
                self.logger.debug(f"Response content: {response.text}")
        except json.JSONDecodeError as json_err:
            self.logger.error(f"JSON decoding error: {json_err} - Response text: {getattr(response, 'text', '')}")
        return None

    def get_auth_token(self):
        """
        Obtains an authentication token from the CrowdStrike API using _make_api_call.
        """
        headers = self._get_headers(
            content_type="application/x-www-form-urlencoded", include_auth=False
        )
        data = {"client_id": self.client_id, "client_secret": self.client_secret}

        self.logger.info("Attempting to get authentication token...")
        token_info = self._make_api_call(
            "POST", self.auth_token_url, headers=headers, data=data
        )

        if token_info:
            self.access_token = token_info.get("access_token")
            if self.access_token:
                self.logger.info("Authentication token obtained successfully.")
                return True
            else:
                self.logger.error("Failed to get access token from response.")
        return False

    def initialize_rtr_session(self, device_id=None):
        """
        Initializes a new Real-time Response session with the cloud using _make_api_call.
        """
        target_device_id = device_id if device_id else self.device_id
        if not target_device_id:
            self.logger.error("Device ID not provided. Cannot initialize RTR session.")
            return False

        headers = self._get_headers()
        params = {"timeout": 30, "timeout_duration": "30s"}
        payload = {"device_id": target_device_id, "queue_offline": False}

        self.logger.info(f"Attempting to initialize RTR session for device: {target_device_id}...")
        session_info = self._make_api_call(
            "POST",
            self.rtr_session_url,
            headers=headers,
            params=params,
            json_data=payload,
        )

        if session_info:
            self.logger.debug("RTR Session Initialization Response: %s", json.dumps(session_info))
            resources = session_info.get("resources")
            if resources and len(resources) > 0:
                self.session_id = resources[0].get("session_id")
                if self.session_id:
                    self.logger.info(f"RTR Session ID: {self.session_id}")
                    return True
            self.logger.error("Failed to get session_id from RTR session initialization response.")
        return False

    def run_rtr_script(
        self, script_name="session-script.ps1", device_id=None, session_id=None
    ):
        """
        Runs an RTR script on a host using _make_api_call.
        """
        target_device_id = device_id if device_id else self.device_id
        target_session_id = session_id if session_id else self.session_id

        if not target_device_id or not target_session_id:
            self.logger.error("Device ID or Session ID not available. Cannot run RTR script.")
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

        self.logger.info(f"Attempting to run RTR script '{script_name}' for session: {target_session_id} on device: {target_device_id}...")
        command_response = self._make_api_call(
            "POST", self.rtr_admin_command_url, headers=headers, json_data=payload
        )

        if command_response:
            self.logger.debug("Run RTR Script Response: %s", json.dumps(command_response))
            resources = command_response.get("resources")
            if resources and len(resources) > 0:
                self.cloud_request_id = resources[0].get("cloud_request_id")
                if self.cloud_request_id:
                    self.logger.info(f"Cloud Request ID for command: {self.cloud_request_id}")
                    return True
            self.logger.error("Failed to get cloud_request_id from run script response.")
        return False

    def get_rtr_command_status(self, cloud_request_id=None, sequence_id=0):
        """
        Gets the status of a single executed RTR administrator command using _make_api_call.
        """
        target_cloud_request_id = (
            cloud_request_id if cloud_request_id else self.cloud_request_id
        )

        if not target_cloud_request_id:
            self.logger.error("Cloud Request ID not available. Cannot get command status.")
            return None

        headers = self._get_headers()
        params = {
            "cloud_request_id": target_cloud_request_id,
            "sequence_id": sequence_id,
        }

        self.logger.info(f"Attempting to get status for command with Cloud Request ID: {target_cloud_request_id}...")
        status_response = self._make_api_call(
            "GET", self.rtr_admin_command_url, headers=headers, params=params
        )

        if status_response:
            # Parse stdout JSON string in each resource
            resources = status_response.get("resources", [])
            for res in resources:
                stdout = res.get("stdout")
                if isinstance(stdout, str):
                    try:
                        res["stdout"] = json.loads(stdout)
                        self.logger.debug("Successfully parsed stdout JSON")
                    except json.JSONDecodeError:
                        self.logger.debug("stdout was not JSON, leaving as string")

            # Log the response
            try:
                pretty = json.dumps(status_response, indent=2)
                self.logger.debug("RTR Command Status Response: %s", pretty)
            except Exception:
                pass
        return status_response


# -------------------------
# Bloodhound Manager (HMAC)
# -------------------------


class BloodhoundManager:
    """Handles BloodHound Enterprise ingestion via HMAC-signed requests.

    Environment variables required:
      - TOKEN_ID
      - TOKEN_KEY (base64 or raw string used as secret)
      - TENANT_DOMAIN (full URL, e.g. https://maplesyrup.bloodhoundenterprise.io/)
    """

    endpoints = {
        "test_connection": "/api/v2/available-domains",
        "ingest_data": "/api/v2/ingest",
        "file_upload_start": "/api/v2/file-upload/start",
        "file_upload_chunk": "/api/v2/file-upload/",  # append id
        "file_upload_end": "/api/v2/file-upload/{id}/end",
    }

    def __init__(self, logger: logging.Logger = None):
        self.logger = logger or logging.getLogger("BloodhoundManager")
        self.token_id = os.getenv("TOKEN_ID")
        token_key = os.getenv("TOKEN_KEY")
        self.tenant_domain = os.getenv("TENANT_DOMAIN")

        if not self.token_id or not token_key or not self.tenant_domain:
            raise ValueError("TOKEN_ID, TOKEN_KEY and TENANT_DOMAIN must be set in .env for BloodHound upload")

        # keep token_key as bytes for HMAC operations
        self.token_key = token_key.encode()

        # ensure tenant domain ends with slash
        if not self.tenant_domain.endswith("/"):
            self.tenant_domain += "/"

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "azurehound/v2.0.7"})

    def _get_full_url(self, key: str, **kwargs) -> str:
        path = self.endpoints.get(key)
        if not path:
            raise ValueError(f"Unknown endpoint key: {key}")
        if kwargs:
            path = path.format(**kwargs)
        return urljoin(self.tenant_domain, path)

    def _get_hmac_headers(self, method: str, uri_path: str, payload_string: str = "") -> dict:
        # Step 1: HMAC-SHA256 with token_key on method+uriPath
        dig1 = hmac.new(self.token_key, (method + uri_path).encode(), hashlib.sha256).digest()

        # Step 2: HMAC with dig1 as key, on truncated datetime
        now = time.time()
        # Create timestamp similar to Go implementation: microseconds and +00:00
        from datetime import datetime, timezone

        dt = datetime.fromtimestamp(now, tz=timezone.utc)
        datetime_formatted = dt.strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")
        truncated = datetime_formatted[:13]

        dig2 = hmac.new(dig1, truncated.encode(), hashlib.sha256).digest()

        # Step 3: HMAC with dig2 as key and include payload for POST
        dig3 = hmac.new(dig2, b"")
        if method.upper() == "POST" and payload_string:
            dig3 = hmac.new(dig2, payload_string.encode(), hashlib.sha256)
        final = dig3.digest()
        signature = base64.b64encode(final).decode()

        headers = {
            "Authorization": f"bhesignature {self.token_id}",
            "RequestDate": datetime_formatted,
            "Signature": signature,
            "Content-Type": "application/json",
        }
        return headers

    def start_file_upload(self) -> int:
        url = self._get_full_url("file_upload_start")
        parsed = urlparse(url)
        headers = self._get_hmac_headers("POST", parsed.path, "")
        headers.update({"Accept": "application/json"})

        self.logger.info("Starting file upload session to: %s", url)
        resp = self.session.post(url, headers=headers, timeout=30)
        if resp.status_code < 200 or resp.status_code >= 300:
            raise RuntimeError(f"Start file upload failed: {resp.status_code} - {resp.text}")

        data = resp.json()
        # Expecting structure: {"data": { ... "id": <int>}}
        upload_id = data.get("data", {}).get("id")
        if not upload_id:
            raise RuntimeError(f"Start response missing upload id: {data}")
        self.logger.info("Successfully started file upload. Upload ID: %s", upload_id)
        return int(upload_id)

    def upload_file_chunk(self, upload_id: int, ingest_type: str, data_list: list):
        endpoint = f"/api/v2/file-upload/{upload_id}"
        url = urljoin(self.tenant_domain, endpoint)
        parsed = urlparse(url)

        payload = {"meta": {"type": ingest_type}, "data": data_list}
        payload_bytes = json.dumps(payload).encode()
        payload_str = payload_bytes.decode()

        headers = self._get_hmac_headers("POST", parsed.path, payload_str)
        headers.update({"Accept": "text/plain"})

        self.logger.info("Uploading %d items to upload ID %d at: %s", len(data_list), upload_id, url)
        resp = self.session.post(url, headers=headers, data=payload_bytes, timeout=60)
        if resp.status_code != 202:
            raise RuntimeError(f"file upload chunk failed for ID {upload_id}: {resp.status_code} - {resp.text}")
        self.logger.info("Successfully uploaded %d items for upload ID %d.", len(data_list), upload_id)

    def end_file_upload(self, upload_id: int):
        endpoint = f"/api/v2/file-upload/{upload_id}/end"
        url = urljoin(self.tenant_domain, endpoint)
        parsed = urlparse(url)
        headers = self._get_hmac_headers("POST", parsed.path, "")
        headers.update({"Accept": "text/plain"})

        self.logger.info("Ending file upload session for ID %d at: %s", upload_id, url)
        resp = self.session.post(url, headers=headers, timeout=30)
        if resp.status_code != 200:
            raise RuntimeError(f"end file upload failed for ID {upload_id}: {resp.status_code} - {resp.text}")
        self.logger.info("Successfully ended file upload session for ID %d.", upload_id)