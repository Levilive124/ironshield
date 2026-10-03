FROM php:8.5-cli

WORKDIR /var/www/html

RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv \
    && rm -rf /var/lib/apt/lists/*

COPY index.php ./
COPY start.sh ./
COPY assets ./assets
COPY includes ./includes
COPY bot ./bot

RUN chmod 755 /var/www/html/start.sh \
    && python3 -m venv /opt/ironshield-bot \
    && /opt/ironshield-bot/bin/python -m pip install --no-cache-dir --disable-pip-version-check -r /var/www/html/bot/requirements.txt

RUN mkdir -p /var/lib/ironshield-team && chmod 700 /var/lib/ironshield-team
ENV PORT=8080
ENV BOT_INTERNAL_URL=http://127.0.0.1:8765
ENV BOT_PYTHON_BIN=/opt/ironshield-bot/bin/python
ENV TEAM_DATA_DIR=/var/lib/ironshield-team
VOLUME ["/var/lib/ironshield-team"]
EXPOSE 8080

CMD ["./start.sh"]
