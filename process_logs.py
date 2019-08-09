import argparse
import json
import difflib
import os
import sys
import urllib2

from boto3 import client
from boto3.session import Session


DEFAULT_CHANNEL = '#test-mbaciu'
DEFAULT_REGION = 'us-east-2'
SLACK_USER = 'repokid-log-parser'


def get_args_parser():
    parser = argparse.ArgumentParser(description='Parse repokid log, post summary on slack. If no filename given, read log from stdin noninteractive.')
    parser.add_argument('filename',
                        nargs='?',
                        help='Log filename',
                        action='store')
    args = parser.parse_args()
    return args, parser


def assume_role(role_name):
    cl = client('sts')
    account_id = cl.get_caller_identity()['Account']
    assume_role_arn = 'arn:aws:iam::{account}:role/{role}'.format(account=account_id, role=role_name)
    response = cl.assume_role(RoleArn=assume_role_arn, RoleSessionName='repokid-process-logs')
    session = Session(aws_access_key_id=response['Credentials']['AccessKeyId'],
                      aws_secret_access_key=response['Credentials']['SecretAccessKey'],
                      aws_session_token=response['Credentials']['SessionToken'])
    return session


def get_client(service):
    repokid_assume_role = os.environ.get('REPOKID_ROLE')
    if repokid_assume_role:
        session = assume_role(repokid_assume_role)
        cl = session.client(service)
    else:
        cl = client(service)
    return cl


def get_sm_secret(secret_id, region):
    secrets_manager = client('secretsmanager', region_name=region)
    secret = secrets_manager.get_secret_value(SecretId=secret_id)
    return secret['SecretString']


def slack_post(slack_url, channel, username, text):
    slack_request = urllib2.Request(slack_url)
    slack_request.add_header('Accept', 'application/json')
    slack_request.add_header('Content-Type', 'application/json')
    payload = {'channel': channel,
               'username': username,
               'text': text}
    response = urllib2.urlopen(slack_request, json.dumps(payload))
    response_code = response.getcode()
    return response_code == 200


def parse_repokid_log(fd):
    account = None
    roles = {}
    policy_str = ''
    START_MARKER = 'Would replace policies for role'
    END_MARKER = '} in account'
    start_seen = False
    # Would replace policies for role qa-ecs-drain-lambda-eu-central-1 with:
    # } in account 786930545984
    for line in fd:
        if START_MARKER in line:
            start_seen = True
            role = line.split()[8]
            continue
        elif start_seen:
            if END_MARKER in line:
                account = line.split()[3]
                policy_str += '}'
                policy_parsed = json.loads(policy_str)
                roles[role] = policy_parsed
                policy_str = ''
                start_seen = False
            else:
                policy_str += line
    return account, roles


def get_iam_role_policy(role, policy, cl):
    policy = cl.get_role_policy(RoleName=role,
                                PolicyName=policy)['PolicyDocument']
    return policy


def list_role_policies(role, cl):
    policies = []
    marker = None
    while True:
        if marker:
            response = cl.list_role_policies(RoleName=role,
                                             Marker=marker)
        else:
            response = cl.list_role_policies(RoleName=role)
        policies += response['PolicyNames']
        if response['IsTruncated'] is True:
            marker = response['Marker']
        else:
            break
    return policies


def find_diffs(a, b):
    if type(a) != list:
        a = json.dumps(a, indent=4).splitlines()
    if type(b) != list:
        b = json.dumps(b, indent=4).splitlines()
    d = difflib.unified_diff(a, b, fromfile='before', tofile='after')
    return('\n'.join(list(d)))


if __name__ == '__main__':
    args, parser = get_args_parser()

    slackhook_secret = os.environ['SLACKHOOK_SECRET']
    slack_channel = os.environ.get('SLACK_CHANNEL', DEFAULT_CHANNEL)
    aws_region = os.environ.get('AWS_REGION', DEFAULT_REGION)
    slack_url = 'https://{e}'.format(e=get_sm_secret(secret_id=slackhook_secret, region=aws_region))

    cl = get_client('iam')

    repokid_account, repokid_roles = None, None
    current_roles = {}
    if args.filename:
        with open('repokid.log') as fd:
            repokid_account, repokid_roles = parse_repokid_log(fd)
    elif not sys.stdin.isatty():
        repokid_account, repokid_roles = parse_repokid_log(sys.stdin)
    else:
        parser.print_help()
        exit()

    for repokid_role in repokid_roles:
        current_roles[repokid_role] = {}
        role_policy_list = list_role_policies(role=repokid_role, cl=cl)
        for policy in role_policy_list:
            policy_document = get_iam_role_policy(role=repokid_role, policy=policy, cl=cl)
            current_roles[repokid_role][policy] = policy_document

    slack_msg = ['*repokid wants to make to following changes:*']
    for role in current_roles:
        slack_msg.append('_Role: {r}_'.format(r=role))
        deleted_policies = [p for p in current_roles[role] if p not in repokid_roles[role]]
        if deleted_policies:
            slack_msg.append('\tDelete policies: {dp}'.format(dp=', '.join(deleted_policies)))
        if current_roles[role]:
            slack_msg.append('\tChange policie(s): {p}'.format(p=', '.join([p for p in repokid_roles[role]])))
        else:
            slack_msg.append('\tChange policies: none')
    slack_post(slack_url=slack_url, channel=slack_channel, username=SLACK_USER, text='\n'.join(slack_msg))
