# syntax=docker/dockerfile:1

# Pinned to the channel in rust-toolchain.toml, which this stage never COPYs —
# so a floating `rust:1` would silently build releases with an unpinned
# compiler. Bump this tag and rust-toolchain.toml together.
FROM rust:1.97.1-alpine@sha256:3c38f3f82c2f3d73da3b38e18d279393a04cb43ddded0e35088a8c3324d40900 AS build
# gcc and musl-dev are already in the base; aws-lc-sys (the rustls crypto
# provider) compiles C from source and needs cmake plus a make generator.
RUN apk add --no-cache cmake make
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release --locked -p bugwarden && \
    cp target/release/bugwarden /out

# Both FROMs carry a digest for the same reason the workflows SHA-pin actions:
# the release's two architecture legs run on separate runners, and a tag
# republished between them would build each from different base contents.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7
ARG VERSION=dev
LABEL org.opencontainers.image.source="https://github.com/plusky/bugwarden" \
      org.opencontainers.image.description="MCP server for Bugzilla with operator-controlled security guards" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}"
COPY --from=build /out /usr/local/bin/bugwarden
# The bare binary falls back to a built-in allow-all policy when --policy is
# absent; naming the mount point here makes the image refuse to start instead.
ENV MCP_TRANSPORT=http \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=8000 \
    BUGWARDEN_POLICY=/etc/bugwarden/policy.toml
EXPOSE 8000
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/bugwarden"]
