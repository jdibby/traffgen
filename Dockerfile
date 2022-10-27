FROM ubuntu:latest

ENV TZ=America/Denver

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    iputils-ping \
    net-tools \
    dnsutils \
    bind9-utils \
    traceroute \
    wget \
    telnet \
    snmpd \
    nmap \
    openssh-client \
    gcc \
    curl \
    musl-dev \
    ntpdate \
    tzdata \
    chrony

RUN pip3 install fastcli requests beautifulsoup4

COPY generator.py endpoints.py ./

ENTRYPOINT ["python3", "generator.py", "--os=debian"]

CMD ["--suite=all", "--size=L", "--loop"]
