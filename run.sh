#!/usr/bin/with-contenv bash

if [ ! -f /data/server-key.der ]; then
    openssl ecparam -name secp256r1 -genkey -out /data/server-key.der -outform der
fi

if [ ! -f /data/server-cert.der ]; then
    openssl pkey -inform der -in /data/server-key.der -outform der -pubout -out /data/server-cert.der
fi

/venv/bin/python3 -m matter_aliro