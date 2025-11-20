# ryu-log.py
import os
import logging
from datetime import datetime
from ryu.base import app_manager


class LoggerApp(app_manager.RyuApp):
    """
    Universal Ryu logger app:
    - Automatically creates a ryu_logs/ folder in the same directory as this file.
    - Saves all Ryu logs (including from other apps like ryu-lb.py) into timestamped log files.
    - Keeps console logging active so you can still see live output.
    """

    def __init__(self, *args, **kwargs):
        super(LoggerApp, self).__init__(*args, **kwargs)

        # 🔹 Always create log folder next to this file (safe for sudo & non-sudo)
        project_dir = os.path.dirname(os.path.abspath(__file__))
        log_dir = os.path.join(project_dir, "ryu_logs")
        os.makedirs(log_dir, exist_ok=True)

        # 🔹 Timestamped log file
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        log_file = os.path.join(log_dir, f"controller_log_{ts}.log")

        # 🔹 Log format and handler setup
        fmt = "%(asctime)s - %(levelname)s - %(name)s - %(message)s"
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter(fmt))
        file_handler.setLevel(logging.INFO)

        # 🔹 Attach handler to root logger (so it captures everything)
        root_logger = logging.getLogger()
        root_logger.addHandler(file_handler)

        # (Optional) Adjust console log format a bit cleaner
        console = logging.StreamHandler()
        console.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
        root_logger.addHandler(console)

        # 🔹 Confirmation messages
        self.logger.info("✅ LoggerApp initialized successfully.")
        self.logger.info(f"📁 Logs folder: {log_dir}")
        self.logger.info(f"📝 Log file created: {log_file}")
