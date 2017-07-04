FROM ubuntu:16.04
ARG destEnv
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -y

RUN apt-get install wget -y
RUN echo "deb http://10.12.1.225/public trusty main" >> /etc/apt/sources.list
RUN wget http://10.12.1.225/public/cs-repo.key -O /tmp/cs-repo.key && apt-key add /tmp/cs-repo.key && rm -f /tmp/cs-repo.key
RUN echo "deb http://10.12.1.225/public xenial $destEnv" >> /etc/apt/sources.list
RUN printf "Package: * \nPin: release a=xenial \nPin-Priority: 3600 \n" > /etc/apt/preferences



RUN apt-get update && apt-get install -y software-properties-common python3-setuptools python3-pip python3-dev libyaml-dev libpq-dev nanomsg nanomsg-dev
RUN easy_install3 -U setuptools
ADD requirements.txt requirements.txt
RUN pip3 install -r requirements.txt -v
RUN pip3 install virtualenv pylint nose nose-cov

#docker build -t cs/aucote .
#docker run --rm -P -v `pwd`:`pwd` -w=`pwd` cs/aucote pylint -f parseable *.py | tee pylint.out
#docker run --rm -P -v `pwd`:`pwd` -w=`pwd` cs/aucote nosetests --with-xunit --with-coverage --cover-erase --cover-xml tests/*
