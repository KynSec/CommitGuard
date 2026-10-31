FROM python:3.12-slim

LABEL org.opencontainers.image.title="CommitGuard"
LABEL org.opencontainers.image.description="Offline-first local security control plane"
LABEL org.opencontainers.image.licenses="Apache-2.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY pyproject.toml README.md LICENSE NOTICE THIRD_PARTY_NOTICES.md ./
COPY core ./core
COPY rules ./rules
COPY main.py install_hook.py gui_server.py gui_actions.py gui_page.py ./
RUN pip install --no-cache-dir .

WORKDIR /workspace
ENTRYPOINT ["commit-guard"]
CMD ["status", "."]
