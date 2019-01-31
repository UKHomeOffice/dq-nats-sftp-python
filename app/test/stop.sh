#!/bin/bash
# Cleanup all test containers by stopping them.
# The images downloaded will stay however.

set -e

docker stop $(docker ps -aq)

exit
