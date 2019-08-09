#!/bin/bash
# REPOKID_ACCOUNT env var configured in the service task definition
cd /usr/src/app
/usr/local/bin/repokid repo_all_roles ${REPOKID_ACCOUNT} | /usr/local/bin/python /usr/src/app/process_logs.py