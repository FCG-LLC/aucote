FROM python:3.6

ARG destEnv

COPY requirements.txt /requirements.txt
COPY internal_deps /internal_deps
RUN pip3 install -r requirements.txt
RUN pip3 install bandit
RUN pip3 install nose
RUN pip3 install coverage
RUN pip3 install pylint


RUN echo "deb http://aptly.cs.int/public trusty main" >> /etc/apt/sources.list
RUN wget http://aptly.cs.int/public/cs-repo.key -O /tmp/cs-repo.key && apt-key add /tmp/cs-repo.key && rm -f /tmp/cs-repo.key

RUN echo "deb http://aptly.cs.int/public xenial $destEnv" >> /etc/apt/sources.list
RUN printf "Package: * \nPin: release a=xenial, o=aptly.cs.int \nPin-Priority: 1600 \n" > /etc/apt/preferences

RUN apt-get update && apt-get install -y nanomsg postgresql-client