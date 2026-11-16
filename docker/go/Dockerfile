ARG GO_IMAGE
FROM ${GO_IMAGE}
ENV GOTOOLCHAIN=local GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org CGO_ENABLED=0
WORKDIR /locks
COPY docker/go/go.mod docker/go/go.sum ./
RUN sha256sum go.mod go.sum > /tmp/locks.sha256 \
 && go mod download && go mod verify \
 && GOPROXY=off go build -mod=readonly -trimpath -o /usr/local/bin/xcaddy github.com/caddyserver/xcaddy/cmd/xcaddy \
 && sha256sum -c /tmp/locks.sha256 \
 && mkdir -p /usr/share/shell-build \
 && go version -m /usr/local/bin/xcaddy > /usr/share/shell-build/xcaddy.txt \
 && go clean -modcache && rm -rf /locks /tmp/locks.sha256
