# 使用官方 Python 3.9 镜像作为基础
FROM python:3.9-slim

# 设置工作目录
WORKDIR /app

# 设置环境变量
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TZ=Asia/Shanghai

# 安装系统依赖（MySQL 客户端库）
RUN apt-get update && apt-get install -y --no-install-recommends \
    default-libmysqlclient-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# 复制依赖文件
COPY requirements.txt /app/requirements.txt

# 安装 Python 依赖
RUN pip install --no-cache-dir -r requirements.txt

# 复制所有项目文件（.dockerignore 会自动排除不需要的文件）
COPY . /app/

# 设置默认命令
ENTRYPOINT ["python", "importer.py"]