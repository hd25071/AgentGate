# syntax=docker/dockerfile:1
ARG PYTHON_IMAGE=python:3.12-slim
FROM ${PYTHON_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_INDEX_URL=${PIP_INDEX_URL:-https://pypi.tuna.tsinghua.edu.cn/simple}

WORKDIR /eval

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# The report is the output that matters; keep it somewhere obvious.
RUN mkdir -p /eval/report

CMD ["python", "runner.py", "--armed", "--repeats", "3", "--out", "report/report.json"]
