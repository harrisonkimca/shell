ARG PREPARED_IMAGE
FROM ${PREPARED_IMAGE}
WORKDIR /app
ENV UV_PYTHON_DOWNLOADS=never UV_COMPILE_BYTECODE=1
COPY pyproject.toml uv.lock .python-version ./
RUN uv sync --python /usr/local/bin/python --locked --no-dev --no-cache --index-url https://pypi.org/simple
COPY apps/api/src /app/src
ENV PATH="/app/.venv/bin:$PATH" PYTHONPATH=/app/src
USER 65532:65532
CMD ["python", "-m", "shell_api.main"]
