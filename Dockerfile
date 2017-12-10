FROM python:3

RUN apt-get update
RUN apt-get -y install iptables libnfnetlink0 libnfnetlink-dev libnetfilter-queue1 libnetfilter-queue-dev tcpdump

WORKDIR xss-prevent/

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY ./* ./
RUN ls -la

CMD python ./sniffer.py --destination $DESTINATION --port $PORT
