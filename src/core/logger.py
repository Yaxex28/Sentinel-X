import logging
from logging.handlers import RotatingFileHandler
from  pathlib import Path

def setup_logger(name:str, log_dir: str, log_level: str= "INFO") -> logging.Logger:
    """
    Create and configure a logger that writes to a rotating log file
    """

    #1 make sure that logging directory actually exits in disk
    Path(log_dir).mkdir(parents=True, exist_ok=True)

    #2 create (or get) a logger with this name
    logger = logging.getLogger(name)
    logger.setLevel(log_level)

    # 3. Create the rotating file handler
    # - file path:log_dir / "sentinel.log"
    # - maxBytes:5,000,000(5MB)
    # - backuocount: 3

    handler = RotatingFileHandler(
     filename = Path(log_dir) / "sentinel.log",
     maxBytes=5_000_000,
     backupCount= 3

    )
    
    #4. Create a formatter and attach it to the handler
    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s"
    )
    handler.setFormatter(formatter)

    logger.addHandler(handler)

    return logger