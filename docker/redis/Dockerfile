ARG REDIS_IMAGE
FROM ${REDIS_IMAGE}
RUN test "$(cut -d. -f1,2 /etc/alpine-release)" = 3.23 \
 && printf '%s\n' https://dl-cdn.alpinelinux.org/alpine/v3.23/main https://dl-cdn.alpinelinux.org/alpine/v3.23/community > /etc/apk/repositories \
 && apk upgrade --no-cache
