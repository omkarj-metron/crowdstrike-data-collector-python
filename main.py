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

        # Process each script
        for idx, script in enumerate(script_names, start=1):
            # Setup logging for this script
            logfile = os.path.join(logs_dir, f"{script.replace(' ', '_')}.log")
            logger = setup_logger(f"script-{idx}", logfile)
            logger.info("--- Processing Script %d/%d: %s ---", idx, len(script_names), script)

            # Initialize clients
            try:
                rtr_client = CrowdStrikeRTR(logger=logger)
            except Exception as e:
                logger.exception("Failed to initialize CrowdStrikeRTR: %s", e)
                continue

            # Only init BloodHound if upload is enabled
            bh_manager: Optional[BloodhoundManager] = None
            if upload_to_bh:
                try:
                    bh_manager = BloodhoundManager(logger=logger)
                except Exception as e:
                    logger.exception("Failed to initialize BloodhoundManager: %s", e)

            # Process this script
            success, results = process_script(
                script_name=script,
                rtr_client=rtr_client,
                bh_manager=bh_manager,
                rtr_result_dir=rtr_result_dir,
                max_retries=max_retries,
                retry_delay=retry_delay,
                upload_to_bh=upload_to_bh,
                logger=logger
            )

            if success:
                logger.info("Successfully processed script %s", script)
                if results:
                    logger.info("Collected %d result items", len(results))
            else:
                logger.error("Failed to process script %s", script)

            logger.info("--- Finished processing script: %s ---\n", script)

    except Exception as e:
        logging.exception("Unhandled error in main: %s", e)
        return 1

    return 0


if __name__ == "__main__":
    exit(main())