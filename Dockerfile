FROM rust:latest

RUN apt-get update && \
    apt-get install -y libpcap-dev nftables curl iputils-ping

WORKDIR /app

CMD ["tail", "-f", "/dev/null"]
