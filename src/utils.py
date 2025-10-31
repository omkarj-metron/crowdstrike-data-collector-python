import os
import logging
from dotenv import load_dotenv


def setup_logger(name: str, logfile: str = None) -> logging.Logger:
    """Create and configure a logger that writes to both file and console."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    # Clear handlers if re-running
    if logger.handlers:
        logger.handlers = []

    fmt = logging.Formatter("[%(asctime)s] %(levelname)s %(name)s:%(lineno)d - %(message)s")
    
    # Console handler (INFO level)
    sh = logging.StreamHandler()
    sh.setLevel(logging.INFO)
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    # File handler if path provided (DEBUG level)
    if logfile:
        fh = logging.FileHandler(logfile)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)
        logger.addHandler(fh)

    return logger


def get_env_config():
    """Load and validate environment configuration."""
    load_dotenv()

    # Required CrowdStrike config
    script_file_names = os.getenv("SCRIPT_FILE_NAMES")
    if not script_file_names:
        raise ValueError("SCRIPT_FILE_NAMES environment variable not set. Provide comma-separated script filenames.")
    script_names = [s.strip() for s in script_file_names.split(",") if s.strip()]

    # Optional config with defaults
    upload_to_bh = os.getenv("UPLOAD_TO_BLOODHOUND", "false").lower() in ("1", "true", "yes")
    
    try:
        max_retries = int(os.getenv("MAX_RETRIES", "10"))
    except ValueError:
        max_retries = 10
    
    try:
        retry_delay = int(os.getenv("RETRY_DELAY", "5"))
    except ValueError:
        retry_delay = 5

    return {
        "script_names": script_names,
        "upload_to_bh": upload_to_bh,
        "max_retries": max_retries,
        "retry_delay": retry_delay
    }


def ensure_directories():
    """Create required directories if they don't exist."""
    dirs = ["logs", "rtr-result"]
    for d in dirs:
        os.makedirs(d, exist_ok=True)
    return dirs