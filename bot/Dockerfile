FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir --disable-pip-version-check -r requirements.txt
COPY main.py ./main.py
COPY cogs ./cogs

ENV BOT_HTTP_HOST=0.0.0.0
ENV BOT_HTTP_PORT=8765
EXPOSE 8765
CMD ["python", "main.py"]
