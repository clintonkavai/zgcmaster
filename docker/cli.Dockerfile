FROM rust:1.96.0@sha256:58fe97504a0e4cbba5d85599619a589923d3e779472a6fb0840d58d1c4ba99d7 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src src
COPY tests tests
RUN cargo test --locked && cargo build --release --locked
FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a
COPY --from=build /src/target/release/zgcmaster /usr/local/bin/zgcmaster
ENTRYPOINT ["zgcmaster"]
