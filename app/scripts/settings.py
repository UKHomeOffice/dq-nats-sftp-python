"""Settings module - used to import the configuration settings from the
environment variables"""

import os

"""DQ NATS file ingest"""
PROCESS_INTERVAL        = int(os.environ.get('PROCESS_INTERVAL', 240))
MAX_BATCH_SIZE          = int(os.environ.get('MAX_BATCH_SIZE', 25))
SSH_REMOTE_HOST         = os.environ.get('SSH_REMOTE_HOST')
SSH_REMOTE_USER         = os.environ.get('SSH_REMOTE_USER')
SSH_PRIVATE_KEY         = os.environ.get('SSH_PRIVATE_KEY')
SSH_LANDING_DIR         = os.environ.get('SSH_LANDING_DIR')
S3_BUCKET_NAME          = os.environ.get('S3_BUCKET_NAME')
S3_KEY_PREFIX           = os.environ.get('S3_KEY_PREFIX')
S3_ACCESS_KEY_ID        = os.environ.get('S3_ACCESS_KEY_ID')
S3_SECRET_ACCESS_KEY    = os.environ.get('S3_SECRET_ACCESS_KEY')
GA_S3_BUCKET_NAME       = os.environ.get('GA_S3_BUCKET_NAME')
GA_S3_KEY_PREFIX        = os.environ.get('GA_S3_KEY_PREFIX')
GA_S3_ACCESS_KEY_ID     = os.environ.get('GA_S3_ACCESS_KEY_ID')
GA_S3_SECRET_ACCESS_KEY = os.environ.get('GA_S3_SECRET_ACCESS_KEY')
CLAMAV_URL              = os.environ.get('CLAMAV_URL')
CLAMAV_PORT             = os.environ.get('CLAMAV_PORT')
SLACK_WEBHOOK           = os.environ.get('SLACK_WEBHOOK')
