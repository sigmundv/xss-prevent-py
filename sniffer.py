# code adapted from https://stackoverflow.com/questions/27551367/http-get-packet-sniffer-in-scapy
# https://gist.github.com/eXenon/85a3eab09fefbb3bee5d
# https://gist.github.com/eXenon/85a3eab09fefbb3bee5d#file-scapy_bridge-py-L19

import uuid
import os
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
        self.chains, self.num_rules = self.set_iptables_rules(destination, ports)
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
            logging.info("Databases %s already exists; do nothing.",
                            ("_users", "_replicator", "_global_changed"))

        # Setup database for application
        dbname = "xssprevent"
        try:
            self.couch.create(dbname)
            self.database = self.couch[dbname]
            logging.info("Database %s initialised.", dbname)
        except couchdb.PreconditionFailed:
            logging.info("Database %s already exists; do nothing.", dbname)

    def set_iptables_rules(self, destination, port):
        """

        :return:
        """
        prerouting_chain = self.iptables.create_chain("PREROUTING")
        # input_chain = self.iptables.create_chain("INPUT")
        # forward_chain = self.iptables.create_chain("FORWARD")
        rules = (IpTables.create_rule(destination=destination, destination_port=p) for p in port)
        num_rules = 0
        for rule in rules:
            IpTables.create_target(rule, "NFQUEUE")
            IpTables.insert_rule(prerouting_chain, rule)
            # IpTables.insert_rule(input_chain, rule)
            # IpTables.insert_rule(forward_chain, rule)
            num_rules += 1
        self.iptables.table.commit()
        self.iptables.table.refresh()
        # chains = (input_chain, output_chain, forward_chain)
        chains = (prerouting_chain,)

        logging.info("iptables rules added")

        return chains, num_rules

    def store_xss_vector(self, payload, category):
        """

        :param category:
        :param payload:
        """
        doc_id = uuid.uuid4().hex
        self.database[doc_id] = {'timeid': arrow.now().timestamp, 'payload': payload, 'xss_vector': category}

    def analyze_packet(self, packet):
        """

        :param packet:
        :return:
        """
        payload = packet.get_payload()
        pkt = scapy.all.IP(payload)
        if pkt.haslayer(self.http_request):
            http_request = pkt.getlayer(self.http_request)
            host = http_request.Host
            method = http_request.Method
            if method == b"GET":
                path = http_request.Path
                logging.debug("%s request path found: %s", method, path)
                return host, [html.escape(unquote(unquote(path.decode("utf-8"))))]
            else:
                raw = http_request.lastlayer()
                try:
                    load = raw.load
                    logging.debug("%s request payload found: %s", method, load)
                    return host, [html.escape(unquote(unquote(load.decode("utf-8"))))]
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
            host, payload = self.analyze_packet(packet)
            logging.DEBUG("Host is: %s ; payload is: %s", str(host), payload)
            category = self.classifier.classify(payload)
            if category:
                logging.info("XSS payload detected ; packet dropped")
                packet.drop()
                Redirector()(target_host=(host+payload[0]), redirect_url=host)
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
        print('unbinding from NFQUEUE')
        logging.info("Unbinding from Netfilter Queue")
        self.nfqueue.unbind()
        logging.info("Deleting iptables rules")
        for chain in self.chains:
            logging.info("Deleting rules from chain %s", chain.name)
            for rule in self.iptables.get_rules(self.iptables.table, chain, self.num_rules):
                logging.debug("Deleting rule %s", rule)
                chain.delete_rule(rule)
        self.iptables.table.refresh()
        self.iptables.table.commit()
        self.iptables.table.refresh()
        self.iptables.table.close()
        logging.info("Deleted iptables rules")


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
        ctx.obj.stop()


# @cli.command()
# @click.pass_obj
# def run(sniffer):
#     """
#
#     :return:
#     """
#     try:
#         sniffer.start()
#     except KeyboardInterrupt:
#         sniffer.stop()


if __name__ == '__main__':
    logging.basicConfig(format="%(asctime)s - %(name)s - %(message)s",
                        filename="logs/server.log",
                        level=logging.DEBUG)
    cli()
