FROM python:3.11-slim
WORKDIR /app

COPY . .
RUN pip install --no-cache-dir -e .

# Overridden by docker-compose; audits the vulnerable server on the compose network.
CMD ["jwtaudit", "audit", "--base-url", "http://vulnerable-server:4000"]
