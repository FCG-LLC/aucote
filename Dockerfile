FROM ubuntu:16.04
ARG destEnv
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -y

RUN apt-get install wget -y
RUN echo "deb http://aptly.cs.int/public trusty main" >> /etc/apt/sources.list
RUN wget http://aptly.cs.int/public/cs-repo.key -O /tmp/cs-repo.key && apt-key add /tmp/cs-repo.key && rm -f /tmp/cs-repo.key
RUN echo "deb http://aptly.cs.int/public xenial $destEnv" >> /etc/apt/sources.list
RUN printf "Package: * \nPin: release a=xenial, o=aptly.cs.int \nPin-Priority: 1600 \n" > /etc/apt/preferences


RUN apt-get update && apt-get install -y software-properties-common libffi-dev python3-setuptools python3-pip python3-dev libyaml-dev libpq-dev libnanomsg5 libnanomsg-dev curl git bash
RUN easy_install3 -U setuptools
ADD internal_deps /internal_deps
ADD requirements.txt requirements.txt
RUN pip3 install -r requirements.txt -v
RUN pip3 install virtualenv pylint nose nose-cov bandit
