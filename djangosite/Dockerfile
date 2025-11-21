FROM ubuntu:22.04
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        apt-utils \
        build-essential \
        ca-certificates \
        curl \
        gcc \
        git \
        gnupg \
        libssl-dev \
        libffi-dev \
        libpcre3-dev \
        nano \
        python3 \
        python3-dev \
        python3-pip \
        python3-venv \
        software-properties-common \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        nodejs \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*

RUN add-apt-repository ppa:oisf/suricata-stable \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        suricata \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir /djangosite
WORKDIR /djangosite

RUN mkdir /nginx

RUN mkdir /venv
RUN python3 -m venv /venv
RUN /venv/bin/python3 -m pip install --upgrade --prefer-binary --compile pip \
    && /venv/bin/python3 -m pip install --upgrade --prefer-binary --compile \
    buildtools \
    setuptools \
    wheel \
    && /venv/bin/python3 -m pip cache purge
ENV PYTHONUNBUFFERED 1

ADD requirements.txt /djangosite/
RUN /venv/bin/python3 -m pip install --prefer-binary --compile -r requirements.txt \
    && /venv/bin/python3 -m pip cache purge


ADD package.json package-lock.json /djangosite/
RUN npm install --omit=dev \
    && npm upgrade --omit=dev \
    && npm audit fix --force \
    && npm cache clean --force

RUN useradd -ms /bin/bash uwsgi
RUN usermod -aG www-data uwsgi
RUN chown uwsgi:www-data -R .

ADD . /djangosite/

RUN mkdir -m ugo+rw /djangosite_dynamic
RUN chown uwsgi:www-data -R /djangosite_dynamic

RUN mkdir /djangosite_data
RUN mkdir -m ugo+rw /djangosite_data/logs
RUN chown uwsgi:www-data -R /djangosite_data

EXPOSE 8080/tcp
VOLUME ["/djangosite", "/djangosite_dynamic", "/djangosite_data"]
ENTRYPOINT ["/bin/sh", "/djangosite/entrypoint.sh"]
