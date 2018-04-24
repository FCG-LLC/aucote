FROM portus.cs.int:5000/prod/cs-base
LABEL maintainer "devops@collective-sense.com"

ARG destEnv

ENV DEBIAN_FRONTEND=noninteractive

RUN echo "deb http://aptly.cs.int/public xenial $destEnv" >> /etc/apt/sources.list
RUN printf "Package: * \nPin: release a=xenial, o=aptly.cs.int \nPin-Priority: 1600 \n" > /etc/apt/preferences
RUN apt-add-repository ppa:pi-rho/security

RUN apt-get update \
    && apt-get install -y \
         gosu \
         aucote \
    && rm -rf /var/lib/apt/lists/*

RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap
RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/masscan

RUN groupadd -g 10014 aucote
RUN adduser --no-create-home --system --shell /bin/false --gecos 'aucote dedicated user' --uid 10014 --gid 10014 --disabled-password aucote

# Capabilities to bind to low ports by other than root users
RUN setcap 'cap_net_bind_service=+ep' /opt/aucote/venv/bin/python

EXPOSE 1235

COPY files/docker-entrypoint.sh /entrypoint.sh
CMD ["/entrypoint.sh"]
