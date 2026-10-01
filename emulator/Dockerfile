FROM python:3.12-slim
# linux データプレーン (VPC / EC2 / ALB の実体) に必要なツール。コンテナは privileged で動かす
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 iptables procps curl util-linux \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml ./
COPY awsemu ./awsemu
RUN pip install --no-cache-dir . && mkdir /data
ENV AWSEMU_HOST=0.0.0.0 AWSEMU_PORT=4566 AWSEMU_STATE_FILE=/data/state.json PYTHONUNBUFFERED=1
EXPOSE 4566
HEALTHCHECK --interval=10s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:4566/_emulator/health')"
CMD ["awsemu", "serve"]
