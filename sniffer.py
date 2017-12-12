# code adapted from https://stackoverflow.com/questions/27551367/http-get-packet-sniffer-in-scapy
# https://gist.github.com/eXenon/85a3eab09fefbb3bee5d
# https://gist.github.com/eXenon/85a3eab09fefbb3bee5d#file-scapy_bridge-py-L19
# https://stackoverflow.com/questions/8440709/stripping-payload-from-a-tcpdump

import uuid
import os
import gc
import arrow
import couchdb
import scapy.all
import scapy_http.http
from netfilterqueue import NetfilterQueue
import logging
from urllib.parse import unquote
import html
import click

# Own modules
from iptables import IpTables
from exceptions import HTTPPacketException
from classifier import Classifier
from redirector import Redirector


class Sniffer:

    def __init__(self, destination, port):
        """
        Initialise iptables rules, netfilterqueue and the classifier.
        """
        self.http_request = scapy_http.http.HTTPRequest
        self.iptables = IpTables()
        ports = port.split(',')
        self.chain, self.num_rules = self.set_iptables_rules(destination, ports)
        self.nfqueue = NetfilterQueue()
        self.classifier = Classifier()
        db_host = os.environ["COUCHDB_HOST"]
        db_user = os.environ["COUCHDB_USER"]
        db_password = os.environ["COUCHDB_PASSWORD"]
        self.couch = couchdb.Server("http://{user}:{password}@{host}:5984/".format(
                                        user=db_user, password=db_password, host=db_host))
        # Do initial setup
        try:
            self.couch.create("_users")
            self.couch.create("_replicator")
            self.couch.create("_global_changes")
        except couchdb.PreconditionFailed:
            logging.info("Databases %s already exist; do nothing.",
                            ("_users", "_replicator", "_global_changed"))

        # Setup database for application
        dbname = "xssprevent"
        try:
            self.couch.create(dbname)
            logging.info("Database %s initialised.", dbname)
        except couchdb.PreconditionFailed:
            logging.info("Database %s already exists; connect to it.", dbname)
        self.database = self.couch[dbname]

    def set_iptables_rules(self, destination, port):
        """

        :return:
        """
        prerouting_chain = self.iptables.create_chain("PREROUTING")
        rules = (IpTables.create_rule(destination=destination, destination_port=p) for p in port)
        num_rules = 0
        for rule in rules:
            IpTables.create_target(rule, "NFQUEUE")
            IpTables.insert_rule(prerouting_chain, rule)
            num_rules += 1
#        self.iptables.table.commit()
#        self.iptables.table.refresh()
#        chains = (prerouting_chain,)

        logging.info("iptables rules added")

        return prerouting_chain, num_rules

    def store_xss_vector(self, source, path, payload, category):
        """

        :param category:
        :param payload:
        """
        doc_id = uuid.uuid4().hex
        self.database[doc_id] = {'timeid': arrow.now().timestamp,
                                    'source': source, 'path': path,
                                    'payload': payload, 'xss_vector': category}

    def analyze_packet(self, packet):
        """

        :param packet:
        :return:
        """
        payload = packet.get_payload()
        pkt = scapy.all.IP(payload)
        source = pkt.src
        if pkt.haslayer(self.http_request):

            http_request = pkt.getlayer(self.http_request)
            host = http_request.Host
            method = http_request.Method
            path = http_request.Path

            if method == b"GET":
                path_split = path.split(b"?")
                path = path_split[0]
                load = b"?".join(path_split[1:])
                logging.debug("%s request path found: %s", method, path)
                return source, host, path.decode("utf-8"), [html.escape(unquote(unquote(load.decode("utf-8"))))]
            else:
                raw = http_request.lastlayer()
                try:
                    load = raw.load
                    logging.debug("%s request payload found: %s", method, load)
                    return source, host, path.decode("utf-8"), [html.escape(unquote(unquote(load.decode("utf-8"))))]
                except AttributeError:
                    logging.exception("No payload in raw packet")
                    raise HTTPPacketException
        else:
            raise HTTPPacketException

    def classify_packet(self, packet):
        """

        :param packet:
        :return:
        """
        try:
            source, host, path, payload = self.analyze_packet(packet)
            pkt = scapy.all.IP(packet.get_payload())
            logging.debug("Host is: %s ; payload is: %s", host, payload)
            category = self.classifier.classify(payload)
            if category:
                logging.info("XSS payload detected ; attack vector stored in DB and packet dropped")
                self.store_xss_vector(source, path, payload[0], str(category[0][0]))
                packet.drop()
            else:
                logging.debug("Packet accepted")
                packet.accept()
        except HTTPPacketException:
            packet.accept()

    def start(self):
        """

        :return:
        """
        logging.info("Netfilter Queue initialised")
        self.nfqueue.bind(0, self.classify_packet)
        logging.info("Bound classification method to Netfilter Queue")
        self.nfqueue.run()
        logging.info("Reading Netfilter Queue")

    def stop(self):
        """

        :return:
        """
        logging.info("Unbinding from Netfilter Queue")
        self.nfqueue.unbind()
        self.chain.flush()
        logging.info("Flushed iptables rules")


@click.group(invoke_without_command=True)
@click.option("--destination", default="127.0.0.1", help="Destination IP for iptables rule. Defaults to localhost.")
@click.option("--port", default="80", help="Port(s) to listen on. "
                                           "Multiple ports should be given as a comma separated list.")
@click.pass_context
def cli(ctx, destination, port):
    ctx.obj = Sniffer(destination, port)
    try:
        ctx.obj.start()
    except KeyboardInterrupt:
        gc.collect()
        ctx.obj.stop()


if __name__ == '__main__':
    logging.basicConfig(format="%(asctime)s - %(name)s - %(message)s",
                        filename="logs/server.log",
                        level=logging.DEBUG)
    cli()
