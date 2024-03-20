FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/output

ENTRYPOINT ["python", "-m", "appsec_gate.cli"]
CMD ["--demo", "--report-only"]
