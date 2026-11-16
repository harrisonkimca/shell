ARG PYTHON_IMAGE
ARG UV_IMAGE
FROM ${UV_IMAGE} AS uv
FROM ${PYTHON_IMAGE}
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /app
ENV UV_PYTHON_DOWNLOADS=never UV_COMPILE_BYTECODE=1
COPY pyproject.toml uv.lock .python-version ./
RUN uv sync --locked --no-dev --no-cache --index-url https://pypi.org/simple
COPY apps/api/src /app/src
ENV PATH="/app/.venv/bin:$PATH" PYTHONPATH=/app/src
USER 65532:65532
CMD ["python", "-m", "shell_api.main"]
