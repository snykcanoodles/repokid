#!/bin/bash
export AWS_REGION
export REPOKID_ROLE
export SLACKHOOK_SECRET
export SLACK_CHANNEL

cd /usr/src/app
# redirect to stdout of pid 1, which in our case (docker) will cause the output to be visible for docker logs
/usr/local/bin/repokid repo_all_roles ${REPOKID_ACCOUNT} | /usr/local/bin/python process_logs.py >> /proc/1/fd/1
