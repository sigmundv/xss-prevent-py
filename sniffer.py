# code adapted from https://stackoverflow.com/questions/27551367/http-get-packet-sniffer-in-scapy
# https://gist.github.com/eXenon/85a3eab09fefbb3bee5d
# https://gist.github.com/eXenon/85a3eab09fefbb3bee5d#file-scapy_bridge-py-L19

import scapy.all
import scapy_http.http
import scapy_ssl_tls.ssl_tls
from netfilterqueue import NetfilterQueue
import logging
from urllib.parse import unquote
import html

# Own modules
from iptables import IpTables
from exceptions import HTTPPacketException
from classifier import Classifier


class Sniffer:

    def __init__(self):
        """
        Initialise iptables rules, netfilterqueue and the classifier.
        """
        self.http_request = scapy_http.http.HTTPRequest
        self.chains, self.rule = self.set_iptables_rules()
        self.nfqueue = NetfilterQueue()
        self.classifier = Classifier()

    @staticmethod
    def set_iptables_rules():
        """

        :return:
        """
        iptables = IpTables()
        output_chain = iptables.create_chain("OUTPUT")
        input_chain = iptables.create_chain("INPUT")
        forward_chain = iptables.create_chain("FORWARD")
        rule = IpTables.create_rule()
        IpTables.create_target(rule, "NFQUEUE")
        IpTables.insert_rule(output_chain, rule)
        IpTables.insert_rule(input_chain, rule)
        IpTables.insert_rule(forward_chain, rule)
        chains = (input_chain, output_chain, forward_chain)

        logging.info("iptables rules added")

        return chains, rule

    def analyze_packet(self, packet):
        """

        :param packet:
        :return:
        """
        payload = packet.get_payload()
        pkt = scapy.all.IP(payload)
        if pkt.haslayer(self.http_request):
            http_request = pkt.getlayer(self.http_request)
            method = http_request.Method
            if method == b"GET":
                path = http_request.Path
                logging.debug("%s request path found: %s", method, path)
                return [html.escape(unquote(unquote(path.decode("utf-8"))))]
            else:
                raw = http_request.lastlayer()
                try:
                    load = raw.load
                    logging.debug("%s request payload found: %s", method, load)
                    return [html.escape(unquote(unquote(load.decode("utf-8"))))]
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
            data = self.analyze_packet(packet)
            category = self.classifier.classify(data)
            if category:
                logging.info("XSS payload detected ; packet dropped")
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
        print('unbinding from NFQUEUE')
        logging.info("Unbinding from Netfilter Queue")
        self.nfqueue.unbind()
        for chain in self.chains:
            chain.delete_rule(self.rule)
        logging.info("Deleting iptables rules")


if __name__ == "__main__":

    logging.basicConfig(format="%(asctime)s - %(name)s - %(message)s",
                        filename="server.log",
                        level=logging.DEBUG)

    sniffer = Sniffer()

    try:
        sniffer.start()
    except KeyboardInterrupt:
        sniffer.stop()
