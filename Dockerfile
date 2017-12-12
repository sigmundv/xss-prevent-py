FROM infoslack/dvwa

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

RUN apt-get update
RUN apt-get -y install python3 python3-dev python3-pip iptables libnfnetlink0 libnfnetlink-dev libnetfilter-queue1 libnetfilter-queue-dev tcpdump

#WORKDIR xss-prevent/

COPY requirements.txt ./
RUN pip3 install pip -U
RUN pip3 install -r requirements.txt

COPY ./ ./

#CMD /run.sh && python3 ./sniffer.py --destination $DESTINATION --port $PORT
