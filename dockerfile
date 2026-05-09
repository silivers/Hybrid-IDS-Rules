# ========== 构建阶段 ==========
FROM python:3.9-slim AS builder

WORKDIR /build

# 先更换 apt 源，再安装编译依赖
RUN sed -i 's/deb.debian.org/mirrors.tuna.tsinghua.edu.cn/g' /etc/apt/sources.list.d/debian.sources 2>/dev/null || \
    sed -i 's/deb.debian.org/mirrors.tuna.tsinghua.edu.cn/g' /etc/apt/sources.list && \
    apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    default-libmysqlclient-dev \
    && rm -rf /var/lib/apt/lists/*

# 复制并下载依赖
COPY requirements.txt /build/
RUN pip install --no-cache-dir --user -r requirements.txt \
    -i https://pypi.tuna.tsinghua.edu.cn/simple

# ========== 运行阶段 ==========
FROM python:3.9-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TZ=Asia/Shanghai \
    PATH=/root/.local/bin:$PATH

# 先更换 apt 源，再安装运行时依赖
RUN sed -i 's/deb.debian.org/mirrors.tuna.tsinghua.edu.cn/g' /etc/apt/sources.list.d/debian.sources 2>/dev/null || \
    sed -i 's/deb.debian.org/mirrors.tuna.tsinghua.edu.cn/g' /etc/apt/sources.list && \
    apt-get update && apt-get install -y --no-install-recommends \
    libmariadb3 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# 从构建阶段复制已安装的依赖
COPY --from=builder /root/.local /root/.local

# 复制项目文件
COPY . /app/

ENTRYPOINT ["python", "importer.py"]