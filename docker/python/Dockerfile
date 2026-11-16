ARG PYTHON_IMAGE
ARG UV_IMAGE
FROM ${UV_IMAGE} AS uv
FROM ${PYTHON_IMAGE}
COPY docker/python/debian.sources /etc/apt/sources.list.d/debian.sources
RUN python -c 'from pathlib import Path; assert not Path("/etc/apt/sources.list").exists(); assert list(Path("/etc/apt/sources.list.d").iterdir()) == [Path("/etc/apt/sources.list.d/debian.sources")]' \
 && apt-get update --error-on=any \
 && apt-get upgrade -y --no-install-recommends \
 && rm -rf /var/lib/apt/lists/* \
 && python -m pip uninstall --yes pip \
 && rm -rf /usr/local/lib/python3.13/ensurepip \
 && rm -f /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.13
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_PYTHON_DOWNLOADS=never
