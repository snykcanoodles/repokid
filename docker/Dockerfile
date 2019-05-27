FROM python:2.7-onbuild

LABEL author="mbaciu@gopro.com"

COPY config_from_env.py config_from_env.py
COPY config.json.j2 config.json.j2

RUN pip install bandit coveralls jinja2 && \
    pip install . && \
    pip install -r test-requirements.txt && \
    python setup.py develop


CMD python config_from_env.py; bash
