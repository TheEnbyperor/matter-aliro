#!/usr/bin/with-contenv bash

if [ ! -d /data/certs ]; then
  mkdir /data/certs
fi

if [ ! -f /data/certs/server-key.der ]; then
  openssl ecparam -name secp256r1 -genkey -out /data/certs/server-key.der -outform der
fi
if [ ! -f /data/certs/server-cert.der ]; then
  openssl pkey -inform der -in /data/certs/server-key.der -outform der -pubout -out /data/certs/server-cert.der
fi

if [ ! -f /data/certs/cd.der ]; then
  /venv/bin/python3 make_cd.py
fi
if [ ! -f /data/certs/dac-cert.pem ]; then
  /venv/bin/python3 make_pai_dac.py
fi

/venv/bin/python3 -m matter_aliro