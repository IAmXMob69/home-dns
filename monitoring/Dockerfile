FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir requests
COPY pihole-exporter.py /app/pihole-exporter.py
EXPOSE 9617
CMD ["python3", "/app/pihole-exporter.py"]
