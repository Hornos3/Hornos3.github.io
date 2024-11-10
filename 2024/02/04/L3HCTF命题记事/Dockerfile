FROM ubuntu:22.04

RUN sed -i 's/archive.ubuntu.com/mirrors.aliyun.com/g' /etc/apt/sources.list && \
    apt update && \
    apt-get -y upgrade && \
    apt-get -y install openssl gcc g++ xinetd lib32z1 netcat net-tools && \
    rm -rf /var/lib/apt/lists/ && \
	rm -rf /root/.cache && \
	apt-get autoclean && \
	rm -rf /tmp/* /var/lib/apt/* /var/cache/* /var/log/*

COPY pwn.xinetd /etc/xinetd.d/ctf
COPY service.sh /service.sh

RUN useradd -m ctf

COPY treasure_hunter /treasure_hunter
COPY flag /flag

RUN chmod 644 /flag && \
    chmod 755 /service.sh && \
    chmod 755 /treasure_hunter

EXPOSE 31778

CMD ["/service.sh"]

USER ctf
