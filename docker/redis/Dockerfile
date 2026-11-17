ARG REDIS_IMAGE
FROM ${REDIS_IMAGE}
RUN printf '%s\n' https://dl-cdn.alpinelinux.org/alpine/v3.23/main https://dl-cdn.alpinelinux.org/alpine/v3.23/community > /etc/apk/repositories \
 && apk upgrade --no-cache
