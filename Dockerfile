FROM python:2.7-slim

LABEL author="mbaciu@gopro.com"

RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app

COPY requirements.txt /usr/src/app/
RUN pip install -r requirements.txt

COPY . /usr/src/app

RUN apt-get update || true && apt install -y cron

RUN pip install bandit coveralls jinja2 && \
    pip install . && \
    pip install -r test-requirements.txt && \
    python setup.py develop

CMD python config_from_env.py; cron -f