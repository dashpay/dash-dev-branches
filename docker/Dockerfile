FROM debian:stretch
LABEL maintainer="Dash Evolution Developers <evodevs@dash.org>"
LABEL description="Dockerised DashCore"

RUN apt-get update && apt-get -y upgrade && rm -fr /var/cache/apt/*

#mainnet
EXPOSE 9998 9999
#testnet
EXPOSE 19998 19999
#regtest
EXPOSE 18332 19994

RUN mkdir -p /dash/.dashcore
WORKDIR /dash
ENV HOME=/dash

VOLUME /data

COPY entrypoint.sh /
COPY bin/* /usr/bin/

COPY dash.conf /dash/dash.conf

ENTRYPOINT ["/entrypoint.sh"]
CMD ["dashd", "-conf=/dash/dash.conf", "-datadir=/data"]
