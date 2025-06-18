ARG PHP_VERSION

FROM mcr.microsoft.com/devcontainers/php:1-${PHP_VERSION}

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive && \
    apt-get install -y libffi-dev && \
    docker-php-ext-install pcntl && \
    apt-get clean -y && rm -rf /var/lib/apt/lists/*

RUN cp /usr/local/etc/php/php.ini-production /usr/local/etc/php/php.ini && \
    sed -i -e "s/^ *memory_limit.*/memory_limit = 512M/g" /usr/local/etc/php/php.ini

# [Optional] Uncomment this section to install additional OS packages.
# RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
#     && apt-get -y install --no-install-recommends <your-package-list-here>

# [Optional] Uncomment this line to install global node packages.
# RUN su vscode -c "source /usr/local/share/nvm/nvm.sh && npm install -g <your-package-here>" 2>&1
