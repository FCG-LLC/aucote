FROM python:3.6
ENV DEBIAN_FRONTEND=noninteractive

COPY requirements.txt /requirements.txt
RUN pip3 install -r /requirements.txt

RUN apt-get update && apt-get install -y nmap masscan cmake tar

RUN wget https://github.com/nanomsg/nanomsg/archive/1.1.5.tar.gz -O /nanomsg.tar.gz
RUN tar xf /nanomsg.tar.gz
RUN cd /nanomsg* && cmake . && make && make install

COPY . /src
COPY dockerization/hardened/files/docker-entrypoint.sh /entrypoint.sh
COPY dockerization/hardened/files/aucote_cfg.yaml.example /aucote_cfg.yaml.example

CMD ["/entrypoint.sh"]
