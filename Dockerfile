FROM ghcr.io/home-assistant/base:latest

COPY run.sh /
COPY matter_aliro /
COPY dac-cert.pem /
COPY dac-priv.pem /
COPY pai-cert.pem /
COPY pai-priv.pem /
RUN chmod a+x /run.sh

CMD [ "/run.sh" ]