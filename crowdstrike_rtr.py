import time
from dotenv import load_dotenv
import os

# Import the CrowdStrikeRTR class from your package
from crowdstrike_manager_class import CrowdStrikeRTR


def main():
    # Load environment variables here, as it's the entry point
    load_dotenv()

    try:
        rtr_client = CrowdStrikeRTR()

        # 1. Get Authentication Token
        if not rtr_client.get_auth_token():
            print("Failed to get authentication token. Exiting.")
            return

        # 2. Initialize RTR Session
        # You can pass device_id here if it's not in .env or you want to override
        if not rtr_client.initialize_rtr_session():
            print("Failed to initialize RTR session. Skipping further API calls.")
            return

        # 3. Run the RTR Script
        # You can specify a different script name here if needed
        if not rtr_client.run_rtr_script(script_name="test-omkar.ps1"):
            print("Failed to run RTR script. Cannot get command status.")
            return

        time.sleep(5)  # Give some time for the command to execute and status to update

        # 4. Get Status of the executed RTR command
        rtr_client.get_rtr_command_status()

    except ValueError as ve:
        print(f"Configuration Error: {ve}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()
