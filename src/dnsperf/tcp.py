from scapy.layers.inet import *
from scapy.layers.dns import *
from scapy.layers.l2 import *
from scapy.layers.http import *
from scapy.all import *


class TCPDNSclient:
    src_ip: RandIP = None
    src_port = RandNum(40000, 50000)
    concurrency: int = None

    def __init__(
        self,
        iface: str,
        src_ip: str,
        dst_ip: str,
        dst_port: int = 53,
        concurrency: int = 1,
    ):
        self.iface = iface
        self.src_ip = RandIP(src_ip)
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.concurrency = concurrency

    def recvsock(self, *args, **kwargs):
        return conf.L3socket(iface=self.iface, *args, **kwargs)

    def send_dns_query(self, data):
        tcp_client = TCP_client.tcplink(
            Raw,
            self.dst_ip,
            self.dst_port,
            self.src_ip,
            recvsock=self.recvsock,
        )

        try:
            for qname, qtype in data:
                dns_query = DNS(rd=1, qd=DNSQR(qname=qname, qtype=qtype))
                length = struct.pack("!H", len(raw(dns_query)))
                tcp_client.send(length + raw(dns_query))
                # response: Raw = tcp_client.recv()
                # response_data = response.load[2:]
                # dns_response = DNS(response_data)
                # dns_response.show2()
            # response: Raw = tcp_client.recv()
            # response_data = response.load[2:]
            # dns_response = DNS(response_data)
            # dns_response.show2()
            time.sleep(20)
        finally:
            tcp_client.close()


client = TCPDNSclient(
    "OpenVPN Data Channel Offload", "110.8.0.0/24", "192.168.21.181", 53
)
queries = []
for i in range(100):
    queries.append((f"w{i + 1}.example.com.", "A"))

client.send_dns_query(queries)
