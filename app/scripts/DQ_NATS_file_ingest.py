#!/usr/bin/python3
"""
# SFTP NATS Script
# Version 3
"""
import re
import os
import sys
import datetime
import logging
from logging.handlers import TimedRotatingFileHandler
import json
import urllib.request
import paramiko
import boto3
import requests

MAX_BATCH_SIZE          = int(os.environ['MAX_BATCH_SIZE'])
SSH_REMOTE_HOST         = os.environ['SSH_REMOTE_HOST']
SSH_REMOTE_USER         = os.environ['SSH_REMOTE_USER']
SSH_PRIVATE_KEY         = os.environ['SSH_PRIVATE_KEY_PATH']
SSH_LANDING_DIR         = os.environ['SSH_LANDING_DIR']
BUCKET_NAME             = os.environ['S3_BUCKET_NAME']
BUCKET_KEY_PREFIX       = os.environ['S3_KEY_PREFIX']
S3_ACCESS_KEY_ID        = os.environ['S3_ACCESS_KEY_ID']
S3_SECRET_ACCESS_KEY    = os.environ['S3_SECRET_ACCESS_KEY']
S3_REGION_NAME          = os.environ['S3_REGION_NAME']
GA_BUCKET_NAME          = os.environ['GA_S3_BUCKET_NAME']
GA_BUCKET_KEY_PREFIX    = os.environ['GA_S3_KEY_PREFIX']
GA_S3_ACCESS_KEY_ID     = os.environ['GA_S3_ACCESS_KEY_ID']
GA_S3_SECRET_ACCESS_KEY = os.environ['GA_S3_SECRET_ACCESS_KEY']
BASE_URL                = os.environ['CLAMAV_URL']
BASE_PORT               = os.environ['CLAMAV_PORT']
SLACK_WEBHOOK           = os.environ['SLACK_WEBHOOK']
DOWNLOAD_DIR            = '/NATS/data/nats'
STAGING_DIR             = '/NATS/stage/nats'
SCRIPTS_DIR             = '/NATS/scripts'
QUARANTINE_DIR          = '/NATS/quarantine/nats'
FAILED_PARSE_DIR        = '/NATS/failed_to_parse/nats'
LOG_FILE                = '/NATS/log/sftp_nats.log'


def ssh_login(in_host, in_user, in_keyfile):
    """
    Login to SFTP
    """
    logger = logging.getLogger()
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.client.AutoAddPolicy())
    privkey = paramiko.RSAKey.from_private_key_file(in_keyfile)
    try:
        ssh.connect(in_host, username=in_user, pkey=privkey)
    except Exception as err:
        logger.error('SSH CONNECT ERROR')
        logger.exception(str(err))
        error = str(err)
        send_message_to_slack(error)
        sys.exit(1)
    return ssh


def run_virus_scan(directory):
    """
    Send a file to scanner API
    """
    logger = logging.getLogger()
    logger.info("Virus Scanning %s folder", directory)
    file_list = os.listdir(directory)
    for scan_file in file_list:
        processing = os.path.join(STAGING_DIR, scan_file)
        with open(processing, 'rb') as scan:
            response = requests.post('http://' + BASE_URL + ':' + BASE_PORT + '/scan', files={'file': scan}, data={'name': scan_file})
            if not 'Everything ok : true' in response.text:
                logger.warning('Virus scan FAIL: %s is dangerous!', scan_file)
                warning = ("Virus scan FAIL: " + scan_file + " is dangerous!")
                file_quarantine = os.path.join(QUARANTINE_DIR, scan_file)
                logger.warning('Move %s from staging to quarantine %s', processing, file_quarantine)
                os.rename(processing, file_quarantine)
                continue
            else:
                logger.info('Virus scan OK: %s', scan_file)
    return True

def send_message_to_slack(text):
    """
    Formats the text and posts to a specific Slack web app's URL
    Returns:
        Slack API repsonse
    """
    logger = logging.getLogger()
    try:
        post = {
            "text": ":fire: :sad_parrot: An error has occured in the *NATS* pod :sad_parrot: :fire:",
            "attachments": [
                {
                    "text": "{0}".format(text),
                    "color": "#B22222",
                    "attachment_type": "default",
                    "fields": [
                        {
                            "title": "Priority",
                            "value": "High",
                            "short": "false"
                        }
                    ],
                    "footer": "Kubernetes API",
                    "footer_icon": "https://platform.slack-edge.com/img/default_application_icon.png"
                }
            ]
            }
        json_data = json.dumps(post)
        req = urllib.request.Request(url=SLACK_WEBHOOK,
                                     data=json_data.encode('utf-8'),
                                     headers={'Content-Type': 'application/json'})
        resp = urllib.request.urlopen(req)
        return resp

    except Exception as err:
        logger.error(
            'The following error has occurred on line: %s',
            sys.exc_info()[2].tb_lineno)
        logger.error(str(err))
        sys.exit(1)

def main():
    """
    Main function
    """
# Setup logging and global variables
    logformat = '%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s'
    form = logging.Formatter(logformat)
    logging.basicConfig(
        format=logformat,
        datefmt='%Y-%m-%d %H:%M:%S',
        level=logging.INFO
    )
    logger = logging.getLogger()
    if logger.hasHandlers():
        logger.handlers.clear()
    loghandler = TimedRotatingFileHandler(LOG_FILE, when="midnight", interval=1, backupCount=7)
    loghandler.suffix = "%Y-%m-%d"
    loghandler.setFormatter(form)
    logger.addHandler(loghandler)
    consolehandler = logging.StreamHandler()
    consolehandler.setFormatter(form)
    logger.addHandler(consolehandler)
    logger.info("Starting")

    # Main
    os.chdir(SCRIPTS_DIR)
    downloadcount = 0
    downloadtostagecount = 0
    uploadcount = 0

# Connect and GET files from SFTP
    logger.info("Connecting via SSH")
    ssh = ssh_login(SSH_REMOTE_HOST, SSH_REMOTE_USER, SSH_PRIVATE_KEY)
    sftp = ssh.open_sftp()
    logger.info("Connected")

    try:
        sftp.chdir(SSH_LANDING_DIR)
        # sort by modified date and get only limited batch
        files = sorted(sftp.listdir(), key=lambda x: sftp.stat(x).st_mtime)
        for file_json in files:
            match = re.search('^\[-PRMD=EG-ADMD=ICAO-C=XX-;MTA-EGGG-1-MTCU_[A-Z0-9]{16}.*\].json$', file_json, re.IGNORECASE)
            download = True
            if match is not None:
                file_json_staging = os.path.join(STAGING_DIR, file_json)

# Protection against redownload
                if os.path.isfile(file_json_staging) and os.path.getsize(file_json_staging) > 0 and os.path.getsize(file_json_staging) == sftp.stat(file_json).st_size:
                    download = False
                    logger.info("Purge %s", file_json)
                    sftp.remove(file_json)
                if download:
                    logger.info("Downloading %s to %s", file_json, file_json_staging)
                    sftp.get(file_json, file_json_staging)  # remote, local
                    downloadtostagecount += 1
                    if os.path.isfile(file_json_staging) and os.path.getsize(file_json_staging) > 0 and os.path.getsize(file_json_staging) == sftp.stat(file_json).st_size:
                        logger.debug("Purge %s", file_json)
                        sftp.remove(file_json)
                    if downloadtostagecount >= MAX_BATCH_SIZE:
                        logger.info("Max batch size reached (%s)", MAX_BATCH_SIZE)
                        break
        sftp.close()
        ssh.close()

    except Exception as err:
        logger.error("Failure getting files from SFTP")
        logger.exception(str(err))
        error = str(err)
        send_message_to_slack(error)
        sys.exit(1)

# Run virus scan
    if run_virus_scan(STAGING_DIR):
        for obj in os.listdir(STAGING_DIR):
            file_download = os.path.join(DOWNLOAD_DIR, obj)
            file_staging = os.path.join(STAGING_DIR, obj)
            # Parse json file
            try:
                with open(file_staging, "r") as q:
                    q.read()
                logger.info("File parsed OK: %s", obj)
            except Exception as err:
                logger.info("Failed to parse file %s. Moving to quarantine directory", file_json)
                file_parsed_failed = os.path.join(FAILED_PARSE_DIR, obj)
                os.rename(file_staging, file_parsed_failed)
                sftp.remove(obj)
                error = str(err)
                err_message = "Failed to parse" + " " + obj + " " + error
                send_message_to_slack(err_message)
            try:
                logger.info("Move %s from staging to download %s", file_staging, file_download)
                os.rename(file_staging, file_download)
                downloadcount += 1
            except Exception as err:
                logger.error("Could not run virus scan on %s", obj)
                logger.exception(str(err))
                error = str(err)
                send_message_to_slack(error)
                sys.exit(1)
    logger.info("Processed %s files", downloadcount)
    if downloadcount == 0:
        logger.warning("Pulling zero files!")
        send_message_to_slack("Something is not right: Pulling zero files! Check SFTP Admin page and contact vendor!")

# Move files to S3
    logger.info("Starting to move files to S3")
    processed_nats_file_list = [filename for filename in os.listdir(DOWNLOAD_DIR)]
    boto_s3_session = boto3.Session(
        aws_access_key_id=S3_ACCESS_KEY_ID,
        aws_secret_access_key=S3_SECRET_ACCESS_KEY,
        region_name=S3_REGION_NAME
    )
    boto_ga_s3_session = boto3.Session(
        aws_access_key_id=GA_S3_ACCESS_KEY_ID,
        aws_secret_access_key=GA_S3_SECRET_ACCESS_KEY,
        region_name=S3_REGION_NAME
    )
    if processed_nats_file_list:
        for filename in processed_nats_file_list:
            s3_conn = boto_s3_session.client("s3")
            ga_s3_conn = boto_ga_s3_session.client("s3")
            full_filepath = os.path.join(DOWNLOAD_DIR, filename)
            if os.path.isfile(full_filepath):
                try:
                    logger.info("Copying %s to DQ S3", filename)
                    time = datetime.datetime.now()
                    dq_bucket_key_timestamp = time.strftime("%Y/%m/%d")
                    s3_conn.upload_file(full_filepath,
                                        BUCKET_NAME,
                                        BUCKET_KEY_PREFIX + "/" + dq_bucket_key_timestamp + "/" + filename)
                except Exception as err:
                    logger.error(
                        "Failed to upload %s, exiting...", filename)
                    logger.exception(str(err))
                    error = str(err)
                    send_message_to_slack(error)
                    sys.exit(1)
                try:
                    logger.info("Copying %s to GA S3", filename)
                    ga_s3_conn.upload_file(full_filepath,
                                           GA_BUCKET_NAME,
                                           GA_BUCKET_KEY_PREFIX + "/" + filename,
                                           ExtraArgs={"ServerSideEncryption": "aws:kms"})
                    os.remove(full_filepath)
                    logger.info("Deleting local file: %s", filename)
                    uploadcount += 1
                except Exception as err:
                    logger.error(
                        "Failed to upload %s, exiting...", filename)
                    logger.exception(str(err))
                    error = str(err)
                    send_message_to_slack(error)
                    sys.exit(1)

    logger.info("Uploaded %s files", uploadcount)

if __name__ == '__main__':
    main()
