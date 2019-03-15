#!/bin/bash

# This script does the following:
# - downloads and runs 3 (three) Docker containers all from public repositories
# - builds a new container from the local repository
# - requests running user to supply values used as variables

set -e

# Set variables

# SFTP connectivity
echo "********************************************"
echo "Setup sftp-server container variables:"
echo "********************************************"
echo "Enter pubkey location (full file path) and press [ENTER]: "
read pubkey
echo "Enter privkey location (full file path) and press [ENTER]: "
read privkey
echo "Enter mountpoint location (full file path) and press [ENTER]: "
read mountpoint

# S3 credentials
echo "********************************************"
echo "Setup NATS container variables"
echo "********************************************"
echo "Enter bucketname and press [ENTER]: "
read bucketname
echo "Enter gabucketname and press [ENTER]: "
read gabucketname
echo "Enter keyprefix and press [ENTER]: "
read keyprefix
echo "Enter gakeyprefix and press [ENTER]: "
read gakeyprefix
echo "Enter awskeyid and press [ENTER]: "
read awskeyid
echo "Enter gaawskeyid and press [ENTER]: "
read gaawskeyid
echo "Enter awssecret and press [ENTER]: "
read awssecret
echo "Enter gaawssecret and press [ENTER]: "
read gaawssecret

# Build SFTP container

function sftp_server {
  run=$(docker run --rm \
        --name sftp-server \
        -v $pubkey:/home/test/.ssh/authorized_keys:ro \
        -v $mountpoint:/home/test/test \
        -p 2222:22 -d atmoz/sftp \
        test::1000
        )
        echo "Created container with SHA: $run"
}

# Build ClamAV container

function clamav {
  run=$(docker run --rm \
        --name clamav \
        -d -p 3310:3310 \
        quay.io/ukhomeofficedigital/clamav
        )
        echo "Created container with SHA: $run"
}

# Build ClamAV REST API container

function clamav_api {
  run=$(docker run --rm \
        --name clamav-api \
        -e 'CLAMD_HOST=clamav' \
        -p 8080:8080 \
        --link clamav:clamav \
        -t -i -d lokori/clamav-rest
        )
        echo "Created container with SHA: $run"
}

# Build NATS container

function nats {
  run=$(docker build -t python/nats --rm ../. && \
        docker run \
        --name nats \
        -e SSH_REMOTE_HOST='sftp-server' \
        -e SSH_REMOTE_USER='test' \
        -e SSH_PRIVATE_KEY_PATH='/home/runner/.ssh/id_rsa' \
        -e SSH_LANDING_DIR='test' \
        -e S3_BUCKET_NAME=$bucketname \
        -e S3_KEY_PREFIX=$keyprefix \
        -e S3_ACCESS_KEY_ID=$awskeyid \
        -e S3_SECRET_ACCESS_KEY=$awssecret \
        -e GA_S3_BUCKET_NAME=$gabucketname \
        -e GA_S3_KEY_PREFIX=$gakeyprefix \
        -e GA_S3_ACCESS_KEY_ID=$gaawskeyid \
        -e GA_S3_SECRET_ACCESS_KEY=$gaawssecret \
        -e CLAMAV_URL='clamav-api' \
        -e CLAMAV_PORT='8080' \
        -v $privkey:/home/runner/.ssh/id_rsa:ro \
        --link clamav-api:clamav-api \
        --link sftp-server:sftp-server \
        -d python/nats
       )
       echo "Created container with SHA: $run"
}

function create_ok_file {
  rand=$(openssl rand -hex 30 | tr "[:lower:]" "[:upper:]" | cut -c -16)
  run=$(echo "{\n  'Test': 'data',\n  'in': 'file'\n}" > "$mountpoint/[-PRMD=EG-ADMD=ICAO-C=XX-;MTA-EGGG-1-MTCU_$rand].json")
  echo "Created OK test file: [-PRMD=EG-ADMD=ICAO-C=XX-;MTA-EGGG-1-MTCU_$rand].json"
}

function create_virus_file {
  rand=$(openssl rand -hex 30 | tr "[:lower:]" "[:upper:]" | cut -c -16)
  run=$(cat ./eicar.com > "$mountpoint/[-PRMD=EG-ADMD=ICAO-C=XX-;MTA-EGGG-1-MTCU_$rand].json")
  echo "Created FAIL test file: [-PRMD=EG-ADMD=ICAO-C=XX-;MTA-EGGG-1-MTCU_$rand].json"
}

function main {
  echo "********************************************"
  echo "Building SFTP-server"
  sftp_server
  echo "Done."
  echo "********************************************"
  echo "Building clamav"
  clamav
  echo "Done."
  echo "********************************************"
  echo "Building clamav-api"
  clamav_api
  echo "Done."
  echo "********************************************"
  echo "Building nats"
  nats
  echo "Done."
  echo "********************************************"
  echo "Generating test files"
  echo "********************************************"
  echo "Creating OK test file"
  create_ok_file
  echo "Done."
  echo "********************************************"
  echo "Creating Virus test file"
  create_virus_file
  echo "Done."
  echo "********************************************"
  echo "Check S3 and verify test files are there also check clamav logs to see the virus being blocked"
  echo "********************************************"
}

main

exit
