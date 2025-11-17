###############################################################################
# Git-based CTF - Sample Vulnerable Service
###############################################################################

FROM i386/debian:latest

# ======================================
# Install dependencies
RUN sed -i 's/deb.debian.org/ftp.daumkakao.com/g' /etc/apt/sources.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        iputils-ping && \
    rm -rf /var/lib/apt/lists/*
# ======================================

RUN mkdir -p /var/ctf
COPY flag /var/ctf/

WORKDIR /srv/app

COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY app/ /srv/app

ENV FLASK_APP=server.py \
    FLASK_RUN_HOST=0.0.0.0 \
    FLASK_RUN_PORT=5000

EXPOSE 5000

ENTRYPOINT [ "flask", "run" ]

