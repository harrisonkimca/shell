ARG BUILDER_IMAGE
ARG CADDY_IMAGE
FROM ${BUILDER_IMAGE} AS build
ARG TARGETARCH
WORKDIR /locks
COPY docker/caddy/go.mod docker/caddy/go.sum ./
RUN sha256sum go.mod go.sum > /tmp/locks.sha256 \
 && go mod download all && go mod verify \
 && sha256sum -c /tmp/locks.sha256 \
 && mkdir -p /out \
 && GOPROXY=off GOOS=linux GOARCH=${TARGETARCH} XCADDY_SKIP_CLEANUP=1 xcaddy build v2.11.9 --replace golang.org/x/net=golang.org/x/net@v0.62.0 --replace github.com/klauspost/compress=github.com/klauspost/compress@v1.20.2 --output /out/caddy \
 && sort go.mod > /tmp/locked.mod \
 && sort /tmp/buildenv*/go.mod > /tmp/effective.mod \
 && cmp /tmp/locked.mod /tmp/effective.mod \
 && sha256sum -c /tmp/locks.sha256
FROM ${CADDY_IMAGE}
COPY --from=build --chown=1001:1001 /out/caddy /usr/bin/caddy
RUN printf '%s\n' https://dl-cdn.alpinelinux.org/alpine/v3.24/main https://dl-cdn.alpinelinux.org/alpine/v3.24/community > /etc/apk/repositories \
 && apk upgrade --no-cache
RUN setcap cap_net_bind_service=+p /usr/bin/caddy
