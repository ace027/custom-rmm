# syntax=docker/dockerfile:1
FROM rust:1.97.0-bookworm AS build
ARG HTTPS_PROXY
ARG https_proxy
WORKDIR /src
COPY . .
ENV SQLX_OFFLINE=true
RUN --mount=type=secret,id=extra_ca,target=/run/secrets/extra_ca \
    if [ -s /run/secrets/extra_ca ]; then \
      cp /run/secrets/extra_ca /usr/local/share/ca-certificates/extra.crt && update-ca-certificates; \
    fi && cargo build --release --locked -p rmm-server

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 rmm
COPY --from=build /src/target/release/rmm-server /usr/local/bin/rmm-server
USER rmm
ENTRYPOINT ["/usr/local/bin/rmm-server"]
