import os
import time
import json
import logging
from typing import Dict, List, Optional, Tuple

from src.crowdstrike_manager import CrowdStrikeRTR, BloodhoundManager


def process_script(
    script_name: str,
    rtr_client: CrowdStrikeRTR,
    bh_manager: Optional[BloodhoundManager],
    rtr_result_dir: str,
    max_retries: int,
    retry_delay: int,
    upload_to_bh: bool,
    logger: logging.Logger,
    device_id: Optional[str] = None
) -> Tuple[bool, Optional[List[Dict]]]:
    """Process a single RTR script and optionally upload results to BloodHound.
    
    Returns:
        Tuple[bool, list]: (success, collected_results)
        - success: True if script completed successfully
        - collected_results: List of result items if any were collected
    """
    # Note: Auth token and RTR session should be initialized before calling this function
    
    # Step 1: run script
    logger.info("Step 1: Running RTR script %s", script_name)
    if not rtr_client.run_rtr_script(script_name=script_name, device_id=device_id):
        logger.error("Failed to run RTR script %s.", script_name)
        return False, None

    # Step 2: poll for status with retries
    logger.info("Step 2: Polling for command status (max_retries=%d, delay=%ds)", max_retries, retry_delay)
    status, results = poll_command_status(rtr_client, max_retries, retry_delay, logger)
    if not status:
        return False, None

    # Verify the response is for the correct device
    if device_id:
        resources = status.get("resources", [])
        if resources:
            response_aid = resources[0].get("aid")
            if response_aid and response_aid != device_id:
                logger.warning("Response device ID mismatch! Expected: %s, Got: %s", device_id, response_aid)
                logger.warning("This may indicate scripts are being run on the wrong device.")

    # Save response to file (if we got this far, we have a status)
    save_response_to_file(status, script_name, rtr_result_dir, logger, device_id=device_id)

    # Upload to BloodHound if enabled and we have results
    if results and upload_to_bh and bh_manager:
        if not upload_to_bloodhound(results, script_name, bh_manager, logger):
            return False, results

    return True, results


def poll_command_status(
    rtr_client: CrowdStrikeRTR,
    max_retries: int,
    retry_delay: int,
    logger: logging.Logger
) -> Tuple[Optional[Dict], Optional[List[Dict]]]:
    """Poll for command completion and parse results.
    
    Returns:
        Tuple[dict, list]: (status_response, collected_results)
        - status_response: Full status response if command completed
        - collected_results: Extracted result items if any were found
    """
    for attempt in range(1, max_retries + 1):
        logger.info("Attempt %d/%d to get command status...", attempt, max_retries)
        status = rtr_client.get_rtr_command_status()
        if not status:
            logger.warning("No status response received on attempt %d. Retrying in %ds...", attempt, retry_delay)
            time.sleep(retry_delay)
            continue

        resources = status.get("resources", [])
        if not resources:
            logger.warning("Status response missing resources on attempt %d. Retrying...", attempt)
            time.sleep(retry_delay)
            continue

        res0 = resources[0]
        if not res0.get("complete"):
            logger.info("Command not yet complete. Sleeping %ds before next attempt...", retry_delay)
            time.sleep(retry_delay)
            continue

        # Command is complete - try to extract results
        stdout = res0.get("stdout", {})
        if isinstance(stdout, dict):
            results = stdout.get("result", [])
            if results:
                logger.info("Successfully extracted %d result items", len(results))
                return status, results
            logger.info("No result items found in stdout")
            return status, None

        logger.warning("Unexpected stdout format")
        return status, None

    logger.error("Command did not complete after %d attempts", max_retries)
    return None, None


def save_response_to_file(
    status: Dict,
    script_name: str,
    rtr_result_dir: str,
    logger: logging.Logger,
    device_id: Optional[str] = None
) -> bool:
    """Save the RTR command response to a JSON file.
    
    Note: rtr_result_dir should already be the device-specific subdirectory if device_id is provided.
    """
    script_safe = script_name.replace(' ', '_')
    # rtr_result_dir should already be device-specific subdirectory, so just use script name
    out_file = os.path.join(rtr_result_dir, f"{script_safe}_response.json")
    try:
        with open(out_file, "w", encoding="utf-8") as fh:
            json.dump(status, fh, indent=2)
        logger.info("Saved RTR response to %s", out_file)
        return True
    except Exception as e:
        logger.exception("Failed to save RTR response: %s", e)
        return False


def upload_to_bloodhound(
    results: List[Dict],
    script_name: str,
    bh_manager: BloodhoundManager,
    logger: logging.Logger
) -> bool:
    """Upload collected results to BloodHound."""
    logger.info("Uploading %d items to BloodHound...", len(results))
    
    try:
        upload_id = bh_manager.start_file_upload()
    except Exception as e:
        logger.exception("Failed to start BloodHound file upload: %s", e)
        return False

    try:
        bh_manager.upload_file_chunk(upload_id, "azure", results)
    except Exception as e:
        logger.exception("Failed to upload chunk: %s", e)
        try:
            bh_manager.end_file_upload(upload_id)
        except Exception as e2:
            logger.exception("Failed to end upload after failed chunk: %s", e2)
        return False

    try:
        bh_manager.end_file_upload(upload_id)
        logger.info("Completed BloodHound upload for script %s (Upload ID: %d)", script_name, upload_id)
        return True
    except Exception as e:
        logger.exception("Failed to end BloodHound upload: %s", e)
        return False