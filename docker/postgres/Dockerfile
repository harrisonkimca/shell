ARG BUILDER_IMAGE
ARG POSTGRES_IMAGE
FROM ${BUILDER_IMAGE} AS build
ARG TARGETARCH
WORKDIR /locks
COPY docker/postgres/go.mod docker/postgres/go.sum ./
RUN sha256sum go.mod go.sum > /tmp/locks.sha256 \
 && go mod download && go mod verify \
 && GOPROXY=off GOOS=linux GOARCH=${TARGETARCH} go build -mod=readonly -trimpath -ldflags='-s -w' -o /out/gosu github.com/tianon/gosu \
 && sha256sum -c /tmp/locks.sha256 \
 && go version -m /out/gosu > /out/gosu.txt
FROM ${POSTGRES_IMAGE}
COPY --from=build /out/gosu /usr/local/bin/gosu
COPY --from=build /out/gosu.txt /usr/share/shell-build/gosu.txt
RUN gosu nobody true
