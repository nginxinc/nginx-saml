FROM php:8.2-apache

# Utilities
RUN apt-get update \
    && apt-get -y install apt-transport-https git curl vim \
        memcached libmemcached-dev zlib1g-dev libxml2-dev --no-install-recommends \
    && apt-get clean -y \
    && pecl install memcached --with-libmemcached-dir=no \
    && docker-php-ext-enable memcached \
    && docker-php-ext-install soap \
    && docker-php-ext-enable soap \
    && rm -r /var/lib/apt/lists/*

# SimpleSAMLphp
ARG SIMPLESAMLPHP_VERSION=1.19.7
RUN curl -s -L -o /tmp/simplesamlphp.tar.gz https://github.com/simplesamlphp/simplesamlphp/releases/download/v$SIMPLESAMLPHP_VERSION/simplesamlphp-$SIMPLESAMLPHP_VERSION.tar.gz && \
    tar xzf /tmp/simplesamlphp.tar.gz -C /tmp && \
    rm -f /tmp/simplesamlphp.tar.gz  && \
    mv /tmp/simplesamlphp-* /var/www/simplesamlphp && \
    touch /var/www/simplesamlphp/modules/exampleauth/enable
COPY saml.crt /var/www/simplesamlphp/cert/
COPY saml.key /var/www/simplesamlphp/cert/
COPY config/simplesamlphp/config.php /var/www/simplesamlphp/config
COPY config/simplesamlphp/authsources.php /var/www/simplesamlphp/config
COPY config/simplesamlphp/saml20-sp-remote.php /var/www/simplesamlphp/metadata
COPY config/simplesamlphp/saml20-idp-hosted.php /var/www/simplesamlphp/metadata
COPY config/simplesamlphp/phpinfo.php /var/www/simplesamlphp/www/admin/

# Apache
ARG ServerName
COPY saml.crt /etc/ssl/cert/saml.crt
COPY saml.key /etc/ssl/private/saml.key
COPY config/apache/ports.conf /etc/apache2
COPY config/apache/simplesamlphp.conf /etc/apache2/sites-available
RUN echo "ServerName $ServerName" >> /etc/apache2/apache2.conf && \
    a2enmod ssl && \
    a2enmod rewrite &&\
    a2dissite 000-default.conf default-ssl.conf && \
    a2ensite simplesamlphp.conf
RUN sed -i '/<Directory \/var\/www\/>/,/<\/Directory>/ s/AllowOverride None/AllowOverride All/' /etc/apache2/apache2.conf
RUN echo "RewriteEngine On" > /var/www/.htaccess
RUN echo "RewriteCond %{REQUEST_FILENAME} !-f" >> /var/www/.htaccess
RUN echo "RewriteCond %{REQUEST_FILENAME} !-d" >> /var/www/.htaccess
RUN echo "RewriteRule ^(.*)$ /simplesaml/admin/phpinfo.php [L,QSA]" >> /var/www/.htaccess
RUN echo "RedirectMatch ^/$ /simplesaml/" >> /var/www/.htaccess

# Autorun memcached and apache
ENTRYPOINT service memcached start && apache2-foreground

# Set work dir
WORKDIR /var/www/simplesamlphp

# General setup
EXPOSE 8080 8443
