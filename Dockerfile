FROM rust:latest AS builder

RUN apt-get update && \
    apt-get install -y libpcap-dev

WORKDIR /usr/src/my-rust-app

COPY . .

RUN cargo build --release

FROM debian:latest

RUN apt-get update && \
    apt-get install -y libpcap-dev nftables curl

WORKDIR /app

COPY --from=builder /usr/src/my-rust-app/target/release/apiserver /app/target/release/apiserver

COPY --from=builder /usr/src/my-rust-app/front /app/front

EXPOSE 3000

CMD ["./target/release/apiserver"]