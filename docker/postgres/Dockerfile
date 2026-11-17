ARG BUILDER_IMAGE
ARG POSTGRES_IMAGE
FROM ${BUILDER_IMAGE} AS build
ARG TARGETARCH
WORKDIR /locks
COPY docker/postgres/go.mod docker/postgres/go.sum ./
RUN sha256sum go.mod go.sum > /tmp/locks.sha256 \
 && go mod download && go mod verify \
 && GOPROXY=off GOOS=linux GOARCH=${TARGETARCH} go build -mod=readonly -trimpath -ldflags='-s -w' -o /out/gosu github.com/tianon/gosu \
 && sha256sum -c /tmp/locks.sha256
FROM ${POSTGRES_IMAGE}
COPY --from=build /out/gosu /usr/local/bin/gosu
RUN gosu nobody true
ENV GOSU_VERSION=1.20
