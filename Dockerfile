FROM ghcr.io/home-assistant/base:latest

RUN apk add --update python3 build-base gcc wget git autoconf automake libtool linux-headers openssl && \
 	wget https://github.com/wolfSSL/wolfssl/archive/refs/tags/v5.8.2-stable.tar.gz -O wolfssl-v5.8.2.tar.gz && \
    tar -xf wolfssl-v5.8.2.tar.gz && \
    cd wolfssl-5.8.2-stable && \
    ./autogen.sh && \
    ./configure CFLAGS="-DDTLS_CID_MAX_SIZE=8 -DWOLFSSL_ALWAYS_VERIFY_CB" --enable-all --enable-debug --enable-secure-renegotiation --enable-sni --enable-dtls --enable-dtls13 --enable-dtlscid --enable-ipv6 --enable-rpk && \
    make -j && \
    make install && \
    cd .. && \
    rm wolfssl-v5.8.2.tar.gz && \
    rm -rf wolfssl-5.8.2-stable && \
	apk del build-base gcc autoconf automake libtool linux-headers

ENV LD_LIBRARY_PATH=/usr/local/lib

RUN mkdir /app
COPY requirements.txt /app
RUN python3 -m venv /venv && /venv/bin/python3 -m pip install -Ur /app/requirements.txt

COPY run.sh /app
COPY cd-signer-cert.pem /app
COPY cd-signer-key.pem /app
COPY paa-cert.pem /app
COPY paa-key.pem /app
COPY make_cd.py /app
COPY make_pai_dac.py /app
COPY matter_aliro /app/matter_aliro
RUN chmod a+x /app/run.sh
WORKDIR /app

CMD [ "/app/run.sh" ]