#!/usr/bin/with-contenv bash

if [ ! -f /data/server-key.der ]; then
    openssl ecparam -name secp256r1 -genkey -out /data/server-key.der -outform der
fi
if [ ! -f /data/server-cert.der ]; then
    openssl pkey -inform der -in /data/server-key.der -outform der -pubout -out /data/server-cert.der
fi

if [ ! -f /data/cd.der ]; then
    /venv/bin/python3 make_cd.py
fi
if [ ! -f /data/dac-cert.pem ]; then
    /venv/bin/python3 make_pai_dac.py
fi

/venv/bin/python3 -m matter_aliro