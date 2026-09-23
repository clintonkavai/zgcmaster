FROM rust:1.98.1@sha256:a8a5f0a1e5fe7dfe1d352591e4a1c7dd2c08fd70475cae872cf3458ba0df0546 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src src
COPY tests tests
RUN cargo test --locked && cargo build --release --locked
FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a
COPY --from=build /src/target/release/zgcmaster /usr/local/bin/zgcmaster
ENTRYPOINT ["zgcmaster"]
