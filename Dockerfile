FROM ghcr.io/home-assistant/base:latest

RUN apk add --update python3
COPY requirements.txt /
RUN python3 -m venv /venv && /venv/bin/python3 -m pip -Ur /requirements.txt

COPY run.sh /
COPY matter_aliro /
COPY dac-cert.pem /
COPY dac-priv.pem /
COPY pai-cert.pem /
COPY pai-priv.pem /
RUN chmod a+x /run.sh

CMD [ "/run.sh" ]