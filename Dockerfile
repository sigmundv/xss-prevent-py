FROM python:3

RUN apt-get update
RUN apt-get -y install libnfnetlink0 libnfnetlink-dev

WORKDIR /home/sigmund/Documents/HDCBIBM/final-project/code/

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD [ "python", "sniffer.py --destination 127.0.0.1 --port 80", "run" ]