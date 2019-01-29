"""Settings module - used to import the configuration settings from the
environment variables"""

import os

"""DQ OAG file ingest"""
PROCESS_INTERVAL            = int(os.environ.get('PROCESS_INTERVAL', 60))
