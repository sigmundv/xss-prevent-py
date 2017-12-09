FROM python:3

RUN apt-get update
RUN apt-get -y install libnfnetlink0 libnfnetlink-dev libnetfilter-queue1 libnetfilter-queue-dev

WORKDIR xss-prevent/

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY . ./

CMD [ "python", "./sniffer.py", "--destination 127.0.0.1 --port 80", "run" ]