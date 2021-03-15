# dq-nats-sftp-python

[![Docker Repository on Quay](https://quay.io/repository/ukhomeofficedigital/dq-nats-sftp-python/status "Docker Repository on Quay")](https://quay.io/repository/ukhomeofficedigital/dq-nats-sftp-python)

A Docker container that runs the following Tasks:
- SFTP LIST files
- SFTP GET from a remote SFTP server
- Running virus check on each file pulled from SFTP by sending them to ClamAV API
- AWS S3 PUT files to an S3 bucket

## Dependencies

- Docker
- Python3.7
- Drone
- AWS CLI
- AWS Keys with PUT access to S3
- Kubernetes

## Structure

- **app/**
  - *Dockerfile*: describe what is installed in the container and the Python file that needs to run
  - *docker-entrypoint.sh*: bash scripts running at container startup
  - *packages.txt*: Python custom Modules
  - *ecosystem.config.js*: declare variables used by PM2 at runtime
  - **bin/**
    - *DQ_NATS_file_ingest*: Python script used with PM2 to declare imported files to PM2 at runtime
  - **scripts/**
    - *__init__.py*: declare Python module import
    - *DQ_NATS_file_ingest.py*: Python3.7 script running within the container
    - *settings.py*: declare variables passed to the *DQ_NATS_file_ingest.py* file at runtime
  - **test/**
    - *start.sh*: Download, build and run Docker containers
    - *stop.sh*: Stop and remove **all** Docker containers
    - *eicar.com*: File containing a test virus string
- **kube/**
  - *deployment.yml*: describe a Kubernetes POD deployment
  - *pvc.yml*: declare a Persistent Volume in Kubernetes
  - *secret.yml*: list the Drone secrets passed to the containers during deployment  
- *.drone.yml*: CI deployment configuration
- *LICENSE*: MIT license file
- *README.md*: readme file

## Kubernetes POD connectivity

The POD consists of 3 (three) Docker containers responsible for handling data.

| Container Name | Function | Language | Exposed port | Managed by |
| :--- | :---: | :---: | ---: | --- |
| dq-nats-data-ingest | Data pipeline app| Python3.7 | N/A | DQ Devops |


## Data flow

- *dq-nats-data-ingest* GET files from an external SFTP server
- *dq-nats-data-ingest* DELETE files from SFTP
- sending these files to *dq-clamav* scanner with destination *dq-clamav:443*
- *OK* or *!OK* response text is sent back to *dq-nats-data-ingest*
  - *IF OK* file is uploaded to S3 and deleted from local storage
  - *IF !OK* file is moved to quarantine on the PVC

## Drone secrets

Environmental variables are set in Drone based on secrets listed in the *.drone.yml* file and they are passed to Kubernetes as required.

## Local Test suite

Testing the NATS Python script can be done by having access to AWS S3 and Docker.
The full stack comprises of 4 Docker containers within the same network linked to each other so DNS name resolution works between the components.

The containers can be started and a couple of test files generated using the *start.sh* script located in **app/test**.
The script will require the following variables passed in at runtime.

|Name|Value|Required|Description|
| --- |:---:| :---:| --- |
| pubkey | /local/path/id_rsa.pub | True | Public SSH key used by the SFTP server|
| privkey | /local/path/id_rsa | True | Private SSH used to connect to the SFTP server|
| mountpoint|  /local/path/mountpoint-dir | True | SFTP source directory|
| bucketname | s3-bucket-name | True | S3 bucket name |
| keyprefix | prefix | True | S3 folder name |
| awskeyid | ABCD | True | AWS access key ID |
| awssecret | abcdb1234 | True | AWS Secret access key |
| webhook | https://hooks.slack.com/services/ABCDE12345 | True | Slack Webhook URL |

- Components:
  - SFTP container
  - NATS Python container

After the script has completed - for the first time it will take around 5 minutes to download all images - there should be a test files in the S3 bucket:

```
[-PRMD=EG-ADMD=ICAO-C=XX-;MTA-EGGG-1-MTCU_YYYYYYYYYYYYYYYY].json
```
The other test file contains a test virus string and it will be located under:

```
/NATS/quarantine/nats/[-PRMD=EG-ADMD=ICAO-C=XX-;MTA-EGGG-1-MTCU_YYYYYYYYYYYYYYYY].json
```

- Launching the test suite

NOTE: navigate to **app/test** first.

```
sh start.sh
```

- When done with testing stop the test suite

NOTE: **all** running containers will be stopped

```
sh stop.sh
```

If files have not uploaded into s3, check the error logs by exec'ing into the nats python container and checking error.log file. The path of this file is shown by entering the command:

```
pm2 show 0
```

If the logs read that the private key found is not a valid format, then cat your id_rsa file to check if the the format is OPENSSH. If you generated your keys specifying RSA type and you still have OPENSSH, then use this command to generate the keys again:

```
ssh-keygen -t rsa -b 4096 -C "email@email.com" -m PEM -f /Path-to-file/id_rsa
```
Some versions of macs auto-format ssh-keys to OPENSSH even when RSA is specified and need to be converted using this command.

## Test using Mock FTP EC2

 in order to test ingesting files in Notprod environemt prior to Prod Deployment. Below are the steps requried:

 - deploy the modified version of *dq-nats-data-ingest* pod to NOTPROD_DATABASE_URL

 - logon to the mock FTP server  via ssh as follows (the EC2 instance *mock-ftp-server-centos* in DQ notprod AWS can sometimes be stopped - so ensure it is running):

 ```
 ssh -i ~/.ssh/test_instance_nonprod.cer centos@35.177.100.82
 ```

 - Once logged on change to the *mock_ftp_user* user and change to the *nats-land* directory. Once in the *nats-land* dir, create a test file. use one of the exiting files as an example.

 - Once the test file is created, monitor the logs of the *dq-nats-data-ingest* pod to check if the test file is ingested, virus scanned, parsed and then pushed to S3 successfully by running the following command:

 ```     
 kubectl --context=acp-notprod_DQ --namespace=dq-apps-notprod logs -f dq-nats-data-ingest-<####>  -c dq-nats-data-ingest
 ```
