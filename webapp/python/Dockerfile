FROM ghcr.io/astral-sh/uv:python3.13-bookworm

RUN \
  --mount=type=cache,target=/var/lib/apt,sharing=locked \
  --mount=type=cache,target=/var/cache/apt,sharing=locked \
  apt-get update -qq && apt-get install -y build-essential default-libmysqlclient-dev

RUN mkdir -p /home/webapp
WORKDIR /home/webapp

COPY pyproject.toml uv.lock .
RUN --mount=type=cache,target=/root/.cache/uv \
  uv sync --compile-bytecode
COPY . .

# Make the run script executable
RUN chmod +x /home/webapp/run_with_xray.sh

ENTRYPOINT [ "/home/webapp/run_with_xray.sh" ]
