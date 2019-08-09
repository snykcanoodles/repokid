#!/bin/bash
export AWS_REGION
export REPOKID_ROLE
export SLACKHOOK_SECRET
export SLACK_CHANNEL

cd /usr/src/app
/usr/local/bin/repokid repo_all_roles ${REPOKID_ACCOUNT} | /usr/local/bin/python process_logs.py
