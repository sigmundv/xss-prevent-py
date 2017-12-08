FROM python:3

WORKDIR /home/sigmund/Documents/HDCBIBM/final-project/code/

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD [ "python", "sniffer.py --destination 127.0.0.1 --port 80", "run" ]