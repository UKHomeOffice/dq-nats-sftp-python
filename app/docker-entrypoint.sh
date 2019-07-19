#!/bin/bash

# Copy all files and folders from the staging area to PVC
cp -R /tmp/NATS/data /NATS
cp -R /tmp/NATS/stage /NATS
cp -R /tmp/NATS/scripts /NATS
cp -R /tmp/NATS/quarantine /NATS
cp -R /tmp/NATS/log /NATS
cp -R /tmp/NATS/bin /NATS
cp -R /tmp/NATS/failed_to_parse /NATS

# Set permissions
chown -R runner:runner /NATS/data
chown -R runner:runner /NATS/stage
chown -R runner:runner /NATS/scripts
chown -R runner:runner /NATS/quarantine
chown -R runner:runner /NATS/log
chown -R runner:runner /NATS/bin
chown -R runner:runner /NATS/failed_to_parse

exec "$@"
