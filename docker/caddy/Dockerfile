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
 && GOPROXY=off GOOS=linux GOARCH=${TARGETARCH} XCADDY_SKIP_CLEANUP=1 xcaddy build v2.11.9 --replace golang.org/x/net=golang.org/x/net@v0.62.0 --output /out/caddy \
 && cmp go.mod /tmp/buildenv*/go.mod
FROM ${CADDY_IMAGE}
COPY --from=build /out/caddy /usr/bin/caddy
