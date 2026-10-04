FROM php:8.4-apache

RUN apt-get update \
    && apt-get install -y --no-install-recommends libpq-dev \
    && docker-php-ext-install pdo_pgsql \
    && a2enmod headers rewrite \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /var/www/html

COPY --chown=www-data:www-data index.php index.html dashboard.html support.html team-login.html team.html ticket.html error.html impressum.html datenschutz.html nutzungsbedingungen.html ./
COPY --chown=www-data:www-data .htaccess ./
COPY --chown=www-data:www-data api/ ./api/
COPY --chown=www-data:www-data assets/ ./assets/
COPY --chown=www-data:www-data includes/storage.php includes/team.php ./includes/
COPY --chown=www-data:www-data bot/discord.php ./bot/discord.php
COPY --chmod=755 container-entrypoint.sh /usr/local/bin/ironshield-entrypoint

RUN printf '%s\n' \
    '<Directory /var/www/html>' \
    '    AllowOverride All' \
    '    Require all granted' \
    '    DirectoryIndex index.html' \
    '</Directory>' \
    > /etc/apache2/conf-available/ironshield.conf \
    && sed -ri 's/Listen 80/Listen 8080/' /etc/apache2/ports.conf \
    && sed -ri 's/<VirtualHost \*:80>/<VirtualHost *:8080>/' /etc/apache2/sites-available/000-default.conf \
    && a2enconf ironshield \
    && mkdir -p /var/lib/ironshield-team \
    && chown -R www-data:www-data /var/lib/ironshield-team \
    && chmod 700 /var/lib/ironshield-team \
    && printf 'upload_max_filesize=5M\npost_max_size=20M\nmax_file_uploads=3\n' > /usr/local/etc/php/conf.d/ironshield.ini

ENV TEAM_DATA_DIR=/var/lib/ironshield-team

VOLUME ["/var/lib/ironshield-team"]
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/ironshield-entrypoint"]
CMD ["apache2-foreground"]
