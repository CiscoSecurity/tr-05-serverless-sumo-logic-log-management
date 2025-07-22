FROM alpine:3.22
LABEL maintainer="Jyoti Verma jyoverma@cisco.com"

ENV PIP_IGNORE_INSTALLED=1

# install packages we need
RUN apk update && apk add --no-cache musl-dev openssl-dev gcc py3-configobj supervisor \
libffi-dev uwsgi-python3 uwsgi-http jq syslog-ng uwsgi-syslog py3-pip python3-dev git

# do the Python dependencies
ADD pyproject.toml poetry.lock /
RUN python -m venv .venv && . ./.venv/bin/activate && pip install --upgrade pip poetry && poetry install

# copy over scripts to init
ADD scripts /
RUN mv /uwsgi.ini /etc/uwsgi
RUN chmod +x /*.py
ADD code /app

# entrypoint
ENTRYPOINT ["/entrypoint.py"]
CMD ["/start.py"]