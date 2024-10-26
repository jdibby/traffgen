FROM alpine:latest

ENV TZ=America/Denver

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apk update && apk add \
    python3 \
    py3-pip \
    musl-dev \
    libc-dev \
    python3-dev \
    iputils-ping \
    net-tools \
    gcc \
    curl \
    chrony \
    tzdata \
    bind-tools \
    wget \
    nmap \
    openssh-client \
    busybox-extras \
    net-snmp

RUN pip3 install fastcli requests colorama beautifulsoup4 tqdm --break-system-packages

ADD https://raw.githubusercontent.com/jdibby/traffgen/main/generator.py ./
ADD https://raw.githubusercontent.com/jdibby/traffgen/main/endpoints.py ./

ENTRYPOINT ["python3", "generator.py"]

CMD ["--suite=all", "--size=M", "--max-wait-secs=5", "--loop"]
