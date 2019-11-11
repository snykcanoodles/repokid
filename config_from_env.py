import os
import jinja2


print('Generating config from env variables...')
aardvark_host = os.environ.get('AARDVARK_APISERVER', '')
repokid_role = os.environ.get('REPOKID_ROLE', '')
aws_region = os.environ.get('AWS_REGION', '')
dynamodb_endpoint = os.environ.get('DYNAMODB_ENDPOINT', '')
dynamodb_region = os.environ.get('DYNAMODB_REGION', '')

with open('config.json.j2') as fd:
    config_template = jinja2.Template(fd.read())

with open('config.json', 'w') as fd:
    print(config_template.render(aardvark_host=aardvark_host,
                                 repokid_role=repokid_role,
                                 aws_region=aws_region,
                                 dynamodb_endpoint=dynamodb_endpoint,
                                 dynamodb_region=dynamodb_region),
          file=fd)
print('Done.')
