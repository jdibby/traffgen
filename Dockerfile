FROM alpine:latest

ENV TZ=America/Denver

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apk update && apk add \
    python3 \
    py3-pip \
    iputils-ping \
    net-tools \
    gcc \
    musl-dev \
    curl \
    chrony \
    tzdata \
    bind-tools \
    wget \
    nmap \
    openssh-client \
    busybox-extras \
    net-snmp

RUN pip3 install fastcli requests beautifulsoup4 --break-system-packages

ADD https://github.com/jdibby/traffgen/generator.py ./
ADD https://github.com/jdibby/traffgen/endpoints.py ./

ENTRYPOINT ["python3", "generator.py", "--os=alpine"]

CMD ["--suite=all", "--size=XL", "--max-wait-secs=5", "--loop"]
