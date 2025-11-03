import os
import logging
from typing import Optional, List

from src.utils import setup_logger, get_env_config, ensure_directories
from src.crowdstrike_manager import CrowdStrikeRTR, BloodhoundManager
from src.rtr import process_script


def main():
    """Main entry point for CrowdStrike RTR data collection."""
    try:
        # Setup required directories
        logs_dir, rtr_result_dir = ensure_directories()

        # Load environment config
        config = get_env_config()
        script_names: List[str] = config["script_names"]
        upload_to_bh: bool = config["upload_to_bh"]
        max_retries: int = config["max_retries"]
        retry_delay: int = config["retry_delay"]

        # Setup logging for initialization steps
        init_logfile = os.path.join(logs_dir, "initialization.log")
        init_logger = setup_logger("initialization", init_logfile)
        
        # Initialize RTR client once before processing scripts
        try:
            rtr_client = CrowdStrikeRTR(logger=init_logger)
        except Exception as e:
            init_logger.exception("Failed to initialize CrowdStrikeRTR: %s", e)
            return 1

        # Get auth token once
        init_logger.info("Step 1: Getting auth token (one time setup)")
        if not rtr_client.get_auth_token():
            init_logger.error("Failed to get authentication token. Exiting.")
            return 1

        # Fetch all devices
        init_logger.info("Step 2: Fetching all devices")
        all_devices = rtr_client.get_all_devices()
        if not all_devices:
            init_logger.error("Failed to fetch devices. Exiting.")
            return 1

        # Filter to only Windows devices
        init_logger.info("Step 3: Filtering Windows devices")
        windows_devices = rtr_client.get_windows_devices(all_devices)
        if windows_devices is None:
            init_logger.error("Failed to get device details. Exiting.")
            return 1

        if not windows_devices:
            init_logger.warning("No Windows devices found. Exiting.")
            return 1

        init_logger.info("Found %d Windows device(s).", len(windows_devices))

        # Check online status of Windows devices
        init_logger.info("Step 4: Checking online status of Windows devices")
        online_devices = rtr_client.get_online_devices(windows_devices)
        if online_devices is None:
            init_logger.error("Failed to check online status. Exiting.")
            return 1

        if not online_devices:
            init_logger.warning("No online Windows devices found. Exiting.")
            return 1

        init_logger.info("Found %d online Windows device(s). Processing scripts for each device.", len(online_devices))

        # Batch initialize RTR sessions for all online Windows devices at once
        init_logger.info("Step 5: Batch initializing RTR sessions for all online Windows devices")
        device_sessions = rtr_client.batch_initialize_rtr_sessions(online_devices)
        if not device_sessions:
            init_logger.error("Failed to batch initialize RTR sessions. Exiting.")
            return 1

        # Filter to only devices that successfully got sessions
        devices_with_sessions = list(device_sessions.keys())
        init_logger.info("Successfully initialized sessions for %d/%d devices", 
                        len(devices_with_sessions), len(online_devices))

        # Only init BloodHound if upload is enabled
        bh_manager: Optional[BloodhoundManager] = None
        if upload_to_bh:
            try:
                bh_manager = BloodhoundManager(logger=init_logger)
            except Exception as e:
                init_logger.exception("Failed to initialize BloodhoundManager: %s", e)

        # Process each device that has a session
        for device_idx, device_id in enumerate(devices_with_sessions, start=1):
            # Create device-specific subdirectories
            device_logs_dir = os.path.join(logs_dir, device_id)
            device_rtr_result_dir = os.path.join(rtr_result_dir, device_id)
            os.makedirs(device_logs_dir, exist_ok=True)
            os.makedirs(device_rtr_result_dir, exist_ok=True)
            
            # Device-level log file in device subdirectory
            device_logfile = os.path.join(device_logs_dir, "device.log")
            device_logger = setup_logger(f"device-{device_idx}", device_logfile)
            device_logger.info("=" * 80)
            device_logger.info("Processing Device %d/%d: %s", device_idx, len(devices_with_sessions), device_id)
            device_logger.info("Session ID: %s", device_sessions[device_id])
            device_logger.info("=" * 80)

            # Process each script for this device
            for script_idx, script in enumerate(script_names, start=1):
                # Setup logging for this script on this device - store in device subdirectory
                script_logfile = os.path.join(device_logs_dir, f"{script.replace(' ', '_')}.log")
                script_logger = setup_logger(f"device-{device_idx}-script-{script_idx}", script_logfile)
                script_logger.info("--- Processing Script %d/%d: %s on Device %s ---", 
                                 script_idx, len(script_names), script, device_id)

                # Process this script - pass device-specific rtr_result_dir
                success, results = process_script(
                    script_name=script,
                    rtr_client=rtr_client,
                    bh_manager=bh_manager,
                    rtr_result_dir=device_rtr_result_dir,
                    max_retries=max_retries,
                    retry_delay=retry_delay,
                    upload_to_bh=upload_to_bh,
                    logger=script_logger,
                    device_id=device_id
                )

                if success:
                    script_logger.info("Successfully processed script %s on device %s", script, device_id)
                    if results:
                        script_logger.info("Collected %d result items", len(results))
                else:
                    script_logger.error("Failed to process script %s on device %s", script, device_id)

                script_logger.info("--- Finished processing script: %s on device: %s ---\n", script, device_id)

            device_logger.info("=" * 80)
            device_logger.info("Finished processing all scripts for Device %s", device_id)
            device_logger.info("=" * 80)

    except Exception as e:
        logging.exception("Unhandled error in main: %s", e)
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
