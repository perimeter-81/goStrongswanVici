FROM ubuntu:22.04
ENV STRONGSWAN_VERSION="5.9.14"
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    DEV_PACKAGES="wget bzip2 make gcc libcurl4-openssl-dev libgmp-dev libssl-dev" && \
    apt-get -y upgrade && \
    apt-get -y install \
    $DEV_PACKAGES && \
    mkdir /strongswan-build && \
    cd /strongswan-build && \
    wget --no-check-certificate https://download.strongswan.org/strongswan-$STRONGSWAN_VERSION.tar.bz2 && \
    tar -xjf strongswan-$STRONGSWAN_VERSION.tar.bz2 && \
    cd strongswan-$STRONGSWAN_VERSION && \
    ./configure --prefix=/usr/local --sysconfdir=/etc --enable-eap-radius  \
    --enable-af-alg --enable-ccm --enable-curl --enable-eap-dynamic --enable-eap-identity  \
    --enable-eap-tls --enable-files --enable-gcm --enable-openssl --enable-error-notify  \
    --enable-chapoly && make all && make install

COPY vici.conf /etc/strongswan.d/charon/vici.conf
