#!/usr/bin/python3
"""
# SFTP NATS Script
# Version 3
"""
import re
import os
import logging
from logging.handlers import TimedRotatingFileHandler
import paramiko
import boto3
import requests

MAX_BATCH_SIZE       = int(os.environ['MAX_BATCH_SIZE'])
SSH_REMOTE_HOST      = os.environ['SSH_REMOTE_HOST']
SSH_REMOTE_USER      = os.environ['SSH_REMOTE_USER']
SSH_PRIVATE_KEY      = os.environ['SSH_PRIVATE_KEY']
SSH_LANDING_DIR      = os.environ['SSH_LANDING_DIR']
BUCKET_NAME          = os.environ['S3_BUCKET_NAME']
BUCKET_KEY_PREFIX    = os.environ['S3_KEY_PREFIX']
S3_ACCESS_KEY_ID     = os.environ['S3_ACCESS_KEY_ID']
S3_SECRET_ACCESS_KEY = os.environ['S3_SECRET_ACCESS_KEY']
S3_REGION_NAME       = os.environ['S3_REGION_NAME']
BASE_URL             = os.environ['CLAMAV_URL']
BASE_PORT            = os.environ['CLAMAV_PORT']
DOWNLOAD_DIR         = '/NATS/data/nats'
STAGING_DIR          = '/NATS/stage/nats'
SCRIPTS_DIR          = '/NATS/scripts'
QUARANTINE_DIR       = '/NATS/quarantine/nats'
LOG_FILE             = '/NATS/log/sftp_nats.log'


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
    except Exception:
        logger.exception('SSH CONNECT ERROR')
    return ssh


def run_virus_scan(filename):
    """
    Send a file to scanner API
    """
    logger = logging.getLogger()
    logger.info("Virus Scanning %s folder", filename)
    # do quarantine move using via the virus scanner
    file_list = os.listdir(filename)
    for scan_file in file_list:
        processing = os.path.join(STAGING_DIR, scan_file)
        with open(processing, 'rb') as scan:
            response = requests.post('http://' + BASE_URL + ':' + BASE_PORT + '/scan', files={'file': scan}, data={'name': scan_file})
            if not 'Everything ok : true' in response.text:
                logger.error('Virus scan FAIL: %s is dangerous!', scan_file)
                file_quarantine = os.path.join(QUARANTINE_DIR, scan_file)
                logger.info('Move %s from staging to quarantine %s', processing, file_quarantine)
                os.rename(processing, file_quarantine)
                return False
            else:
                logger.info('Virus scan OK: %s', scan_file)
    return True


def main():
    """
    Main function
    """
    logging.basicConfig(
        format="%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s",
        datefmt='%Y-%m-%d %H:%M:%S',
        level=logging.INFO
    )
    logger = logging.getLogger()
    loghandler = TimedRotatingFileHandler(LOG_FILE, when="midnight", interval=1, backupCount=7)
    logger.addHandler(loghandler)
    logger.info("Starting")

    # Main
    os.chdir(SCRIPTS_DIR)
    downloadcount = 0
    downloadtostagecount = 0
    uploadcount = 0
    logger.info("Connecting via SSH")
    ssh = ssh_login(SSH_REMOTE_HOST, SSH_REMOTE_USER, SSH_PRIVATE_KEY)
    logger.info("Connected")
    sftp = ssh.open_sftp()

    try:
        sftp.chdir(SSH_LANDING_DIR)
        # sort by modified date and get only limited batch
        files = sorted(sftp.listdir(), key=lambda x: sftp.stat(x).st_mtime)
        for file_json in files:
            match = re.search('^\[-PRMD=EG-ADMD=ICAO-C=XX-;MTA-EGGG-1-MTCU_[A-Z0-9]{16}.*\].json$', file_json, re.I)
            download = True
            if match is not None:
                file_json_staging = os.path.join(STAGING_DIR, file_json)

                #protection against redownload
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
        # end for
    except Exception:
        logger.exception("Failure")
# end with

# batch virus scan on STAGING_DIR for NATS
    if run_virus_scan(STAGING_DIR):
        for obj in os.listdir(STAGING_DIR):
            try:
                file_download = os.path.join(DOWNLOAD_DIR, obj)
                file_staging = os.path.join(STAGING_DIR, obj)
                logger.info("Move %s from staging to download %s", file_staging, file_download)
                os.rename(file_staging, file_download)
                downloadcount += 1
            except Exception:
                logger.exception("Could not run virus scan on %s", obj)
                break
    logger.info("Downloaded %s files", downloadcount)

# Move files to S3
    logger.info("Starting to move files to S3")
    processed_nats_file_list = [filename for filename in os.listdir(DOWNLOAD_DIR)]
    boto_s3_session = boto3.Session(
        aws_access_key_id=S3_ACCESS_KEY_ID,
        aws_secret_access_key=S3_SECRET_ACCESS_KEY,
        region_name=S3_REGION_NAME
    )
    if processed_nats_file_list:
        for filename in processed_nats_file_list:
            s3_conn = boto_s3_session.client("s3")
            full_filepath = os.path.join(DOWNLOAD_DIR, filename)
            logger.info("Copying %s to S3", filename)
            if os.path.isfile(full_filepath):
                s3_conn.upload_file(full_filepath, BUCKET_NAME, BUCKET_KEY_PREFIX + "/" + filename)
                os.remove(full_filepath)
                logger.info("Deleting local file: %s", filename)
                uploadcount += 1
            else:
                logger.error("Failed to upload %s", filename)

    logger.info("Uploaded %s files", uploadcount)

# end def main

if __name__ == '__main__':
    main()
