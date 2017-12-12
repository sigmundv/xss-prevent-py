#!/bin/sh

apt-get update

apt-get install -y procps iptables libnfnetlink0 libnfnetlink-dev libnetfilter-queue1 libnetfilter-queue-dev tcpdump \
                    python3 python3-dev python3-pip \
                    build-essential git
pip3 install -U pip
pip3 install -U -r requirements.txt
