FROM python:3.7-slim

WORKDIR /usr/src/app
COPY . .

LABEL author="mbaciu@gopro.com"

ENV REPOKID_ACCOUNT=''
ENV REPOKID_CRONJOB_SPEC='0 0 * * *'

RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app

COPY requirements.txt /usr/src/app/
RUN pip install -r requirements.txt

COPY . /usr/src/app

RUN apt-get update || true && apt install -y cron

RUN pip install bandit coveralls jinja2 && \
    pip install . && \
    pip install -r requirements-test.txt && \
    pip install -r gopro-requirements.txt && \
    python setup.py develop

COPY repokid.cronjob /etc/cron.d/repokid
RUN chmod 0644 /etc/cron.d/repokid
CMD /usr/src/app/start.sh
