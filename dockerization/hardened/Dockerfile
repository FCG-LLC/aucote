FROM portus.cs.int:5000/prod/cs-base

ARG destEnv

ENV DEBIAN_FRONTEND=noninteractive

RUN echo "deb http://10.12.1.225/public xenial $destEnv" >> /etc/apt/sources.list
RUN printf "Package: * \nPin: release a=xenial, o=10.12.1.225 \nPin-Priority: 1600 \n" > /etc/apt/preferences
RUN apt-add-repository ppa:pi-rho/security
RUN apt-get update

RUN apt-get install -y mq-broker aucote

RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap
RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/masscan

RUN groupadd -g 10014 aucote
RUN adduser --no-create-home --system --shell /bin/false --gecos 'aucote dedicated user' --uid 10014 --gid 10014 --disabled-password aucote

RUN apt-get install -y python-pip && pip install supervisor-stdout

ADD files/supervisor_aucote.conf /etc/supervisor/conf.d/
ADD files/supervisor_mq-broker-aucote.conf /etc/supervisor/conf.d/
ADD files/aucote-daemon.sh /

EXPOSE 1235

CMD /usr/bin/supervisord -n
