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


def src_ip_iter(src_ip: str):
    network = ipaddress.ip_network(src_ip)

    while True:
        for ip in network.hosts():
            yield str(ip)


def generate_data(file_path: str, src_ip: str):
    list = []

    ip_iter = src_ip_iter(src_ip)
    with open(file_path, "r") as f:
        for line in f:
            if not line.strip():
                continue
            strs = line.strip().split()
            qname = strs[0]
            qtype = strs[1]
            times = strs[2] if len(strs) > 2 else 1
            for _ in range(int(times)):
                ip = next(ip_iter)
                list.append((ip, qname, qtype))

    return list


def build_pcap(
    pcap_file: str,
    data_infos,
    src_mac: str,
    dst_mac: str,
    dst_ip: str,
    ecs: str = None,
):
    ether_layer = Ether(src=src_mac, dst=dst_mac)
    udp_layer = UDP(dport=53)

    if ecs:
        network = ipaddress.ip_network(ecs)
        dns_ar = DNSRROPT(
            rdata=(
                EDNS0ClientSubnet(
                    family=1,
                    address=network.network_address,
                    source_plen=network.prefixlen,
                )
            )
        )

    with PcapWriter(pcap_file, linktype=1) as pcap_writer:
        for j, (ip, qname, qtype) in enumerate(data_infos):
            if j % 10000 == 0 and j != 0:
                click.echo(f"write {j} packets in {pcap_file}")

            ip_layer = IP(src=ip, dst=dst_ip)

            dns_layer = DNS(
                rd=1,
                qd=DNSQR(
                    qname=qname,
                    qtype=qtype,
                ),
            )
            if ecs:
                dns_layer.ar = dns_ar

            packet = ether_layer / ip_layer / udp_layer / dns_layer
            pcap_writer.write(packet)

    click.echo(f"write {len(data_infos)} packets done in {pcap_file}")


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
@click.option("-d", "--domain-file", required=True)
@click.option("--src-mac", required=True)
@click.option("--dst-mac", required=True)
@click.option("--src-ip", required=True)
@click.option("--dst-ip", required=True)
@click.option("-o", "--output", required=True)
@click.option("--ecs")
@click.pass_context
def build(
    ctx,
    domain_file: str,
    output: str,
    src_mac: str,
    dst_mac: str,
    src_ip: str,
    dst_ip: str,
    ecs: str,
):
    data = generate_data(domain_file, src_ip)
    if ctx.obj["debug"]:
        pass

    process_list: List[Process] = []
    tmp_file_list: List[str] = []

    cc = cpu_count()
    for i in range(cc):
        start = i * len(data) // cc
        end = (i + 1) * len(data) // cc
        data_list = data[start:end]

        tmp_file = f"{output}.{i}"
        tmp_file_list.append(tmp_file)

        p = Process(
            target=build_pcap, args=(tmp_file, data_list, src_mac, dst_mac, dst_ip, ecs)
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
@click.option("--pps", default=1)
def send(pcap_file: str, iface: str, pps: int):
    cmd = f"tcpreplay -i {iface} --pps {pps} --loop=0 {pcap_file}"
    try:
        click.echo(f"Replaying {pcap_file}...")
        subprocess.run(cmd, shell=True, check=True)
        click.echo(f"Successfully replayed {pcap_file}")
    except subprocess.CalledProcessError as e:
        click.echo(f"Error replaying pcap: {e}")


if __name__ == "__main__":
    cli()
