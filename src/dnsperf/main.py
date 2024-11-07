import ipaddress
from multiprocessing import Process, cpu_count
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.dns import *
from scapy.layers.l2 import *
import click


@click.group()
@click.option("--debug", is_flag=True, help="Enable debug mode.")
@click.pass_context
def cli(ctx, debug):
    ctx.ensure_object(dict)
    ctx.obj["debug"] = debug


def generate_data(file_path: str):
    list = []

    with open(file_path, "r") as f:
        for line in f:
            if not line.strip():
                continue
            strs = line.strip().split()
            qname = strs[0]
            qtype = strs[1]
            times = strs[2] if len(strs) > 2 else 1
            for _ in range(int(times)):
                list.append({"qname": qname, "qtype": qtype})

    return list


class DNSQREnumeration(Packet):
    data: list
    index: int

    def __init__(self, data: list) -> None:
        super().__init__()

        self.index = 0
        self.data = data

    def __next__(self):
        dnsqr = DNSQR(
            qname=self.data[self.index]["qname"],
            qtype=self.data[self.index]["qtype"],
        )

        self.index += 1
        if self.index >= len(self.data):
            self.index = 0

        return dnsqr

    def __iter__(self):
        return self

    def copy(self):
        return DNSQREnumeration(self.data)


def build_pcap(
    pcap_file: str,
    data,
    src_mac: str,
    dst_mac: str,
    src_ip: str,
    dst_ip: str,
    ecs: str = None,
):
    ether_layer = Ether(src=src_mac, dst=dst_mac)
    if ":" in src_ip:
        ip_layer = IPv6(src=RandIP6(src_ip), dst=dst_ip)
    else:
        ip_layer = IP(src=RandIP(src_ip), dst=dst_ip)
    udp_layer = UDP(sport=RandNum(40000, 60000), dport=53)
    dns_layer = DNS(
        rd=1,
        qd=DNSQREnumeration(data),
    )

    if ecs:
        network = ipaddress.ip_network(ecs)
        dns_layer.ar = DNSRROPT(
            rdata=(
                EDNS0ClientSubnet(
                    family=1,
                    address=network.network_address,
                    source_plen=network.prefixlen,
                )
            )
        )

    packet = ether_layer / ip_layer / udp_layer / dns_layer

    with PcapWriter(pcap_file, linktype=1) as pcap_writer:
        pcap_writer.write_header(Ether())
        for i in range(len(data)):
            if i % 10000 == 0 and i != 0:
                click.echo(f"write {i} packets in {pcap_file}")
            pcap_writer.write_packet(packet, sec=0)

    click.echo(f"write {len(data)} packets done in {pcap_file}")


def merge_pcaps(input_files, output_file):
    with open(output_file, "wb") as outfile:
        with open(input_files[0], "rb") as first_file:
            outfile.write(first_file.read())

        for pcap_file in input_files[1:]:
            with open(pcap_file, "rb") as f:
                f.seek(24)
                outfile.write(f.read())

    for pcap_file in input_files:
        os.remove(pcap_file)

    print(f"Successfully merged {input_files} into {output_file}")


@cli.command()
@click.option("-f", "--file", required=True)
@click.option("--src-mac", required=True)
@click.option("--dst-mac", required=True)
@click.option("--src-ip", required=True)
@click.option("--dst-ip", required=True)
@click.option("-o", "--output", required=True)
@click.option("--ecs")
@click.pass_context
def build(
    ctx,
    file: str,
    output: str,
    src_mac: str,
    dst_mac: str,
    src_ip: str,
    dst_ip: str,
    ecs: str,
):
    data = generate_data(file)
    if ctx.obj["debug"]:
        pass

    process_list: List[Process] = []
    tmp_file_list: List[str] = []

    cpu = cpu_count()
    for i in range(cpu):
        start = i * len(data) // cpu
        end = (i + 1) * len(data) // cpu
        data_list = data[start:end]

        tmp_file = f"{output}.{i}"
        tmp_file_list.append(tmp_file)

        p = Process(
            target=build_pcap,
            args=(tmp_file, data_list, src_mac, dst_mac, src_ip, dst_ip, ecs),
        )
        process_list.append(p)
        p.start()

    for p in process_list:
        p.join()

    merge_pcaps(tmp_file_list, output_file=output)
    click.echo(f"Successfully built {output}")


@cli.command()
@click.option("-f", "--pcap-file", required=True)
@click.option("-i", "--iface", required=True)
@click.option("-p", "--pps", type=int)
@click.option("-M", "--mbps", type=int)
@click.option("--loop", default=0)
@click.option("--stats", default=1)
def send(pcap_file: str, iface: str, pps: int, mbps: int, stats: int, loop: int):
    cmd = f"tcpreplay -i {iface} -K --loop={loop} --no-flow-stats"
    if pps:
        cmd += f" --pps={pps}"
    elif mbps:
        cmd += f" --mbps={mbps}"
    else:
        click.echo("pps or mbps must be set")
        return

    if stats:
        cmd += f" --stats={stats}"

    cmd += f" {pcap_file}"

    subprocess.run(cmd, shell=True)

    click.echo(f"Successfully sent {pcap_file} with {pps} pps on {iface}")


if __name__ == "__main__":
    cli()
