import ipaddress
from multiprocessing import Process, cpu_count
import threading
import subprocess
import os
import sys
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
    if not file_path:
        return generate_data_from_stdin()

    return generate_data_from_file(file_path)


def generate_data_from_stdin():
    list = []
    click.echo("Please input the data, format: qname qtype [times]")
    for line in sys.stdin:
        if not line:
            break
        strs = line.strip().split()
        qname = strs[0]
        qtype = strs[1]
        times = strs[2] if len(strs) > 2 else 1
        for _ in range(int(times)):
            list.append({"qname": qname, "qtype": qtype})

    return list


def generate_data_from_file(file_path):
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


def get_route_info(target_ip):
    iface, output_ip, gateway_ip = conf.route.route(target_ip)
    return iface, output_ip, gateway_ip


def get_dst_mac(interface: str, dst_ip: str, gateway_ip: str):
    if gateway_ip == "0.0.0.0":
        arp_request = ARP(pdst=dst_ip)
    else:
        arp_request = ARP(pdst=gateway_ip)

    # 构造 ARP 请求包
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    # 发送 ARP 请求，等待回应
    answered_list = srp(
        arp_request_broadcast, timeout=1, verbose=False, iface=interface
    )[0]

    if answered_list:
        dst_mac = answered_list[0][1].hwsrc
        return dst_mac
    else:
        return None


@cli.command()
@click.option("-f", "--file")
@click.option("--src-mac")
@click.option("--dst-mac")
@click.option("--src-ip")
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
    iface, output_ip, gateway_ip = get_route_info(dst_ip)
    if not src_ip:
        src_ip = output_ip
    if not src_mac:
        src_mac = get_if_hwaddr(iface)
    if not dst_mac:
        dst_mac = get_dst_mac(iface, dst_ip, gateway_ip)

    click.echo(
        f"iface: {iface}, gateway: {gateway_ip}, src_mac: {src_mac}, dst_mac: {dst_mac}, src_ip: {output_ip}, dst_ip: {dst_ip}\n"
    )

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
@click.option(
    "-t", "--threads", default=1, help="Number of threads to use for sending packets"
)
@click.option(
    "--output-mode",
    type=click.Choice(["interleaved", "grouped", "separate"]),
    default="grouped",
    help="Output mode: interleaved (混合输出), grouped (分组输出), separate (分离输出)",
)
def send(
    pcap_file: str,
    iface: str,
    pps: int,
    mbps: int,
    stats: int,
    loop: int,
    threads: int,
    output_mode: str,
):
    if threads < 1:
        click.echo("Threads must be at least 1")
        return

    base_cmd = f"tcpreplay -i {iface} -K --loop={loop}"

    if pps:
        # 将总pps平均分配给每个线程
        thread_pps = pps // threads
        base_cmd += f" --pps={thread_pps}"
    elif mbps:
        # 将总mbps平均分配给每个线程
        thread_mbps = mbps // threads
        base_cmd += f" --mbps={thread_mbps}"
    else:
        click.echo("pps or mbps must be set")
        return

    if stats:
        base_cmd += f" --stats={stats}"

    base_cmd += f" {pcap_file}"

    # 定义ANSI颜色代码
    colors = [
        "\033[31m",  # 红色
        "\033[32m",  # 绿色
        "\033[33m",  # 黄色
        "\033[34m",  # 蓝色
        "\033[35m",  # 紫色
        "\033[36m",  # 青色
        "\033[91m",  # 亮红色
        "\033[92m",  # 亮绿色
        "\033[93m",  # 亮黄色
        "\033[94m",  # 亮蓝色
        "\033[95m",  # 亮紫色
        "\033[96m",  # 亮青色
    ]
    reset_color = "\033[0m"  # 重置颜色

    # 创建线程锁用于同步输出
    output_lock = threading.Lock()

    # 为每个线程创建输出缓冲区
    thread_outputs = {i + 1: [] for i in range(threads)}

    def run_tcpreplay(cmd, thread_id):
        thread_color = colors[(thread_id - 1) % len(colors)]

        with output_lock:
            click.echo(f"{thread_color}Thread {thread_id} starting: {cmd}{reset_color}")

        # 使用Popen而不是run，这样可以实时获取输出
        process = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1,
        )

        # 根据输出模式处理输出
        if output_mode == "interleaved":
            # 交错模式：直接输出，但带有颜色和线程ID前缀
            for line in process.stdout:
                with output_lock:
                    click.echo(
                        f"{thread_color}Thread {thread_id}: {line.strip()}{reset_color}"
                    )

        elif output_mode == "grouped":
            # 分组模式：收集一组输出（例如统计信息），然后一次性输出
            buffer = []
            for line in process.stdout:
                buffer.append(line.strip())
                # 当收集到统计信息或缓冲区达到一定大小时输出
                if "Actual: " in line or "Retried packets (EAGAIN): " in line:
                    with output_lock:
                        click.echo(
                            f"{thread_color}--- Thread {thread_id} Output ---{reset_color}"
                        )
                        for buffered_line in buffer:
                            click.echo(f"{thread_color}{buffered_line}{reset_color}")
                        click.echo(
                            f"{thread_color}------------------------{reset_color}"
                        )
                    buffer = []

            # 输出剩余的缓冲区内容
            if buffer:
                with output_lock:
                    click.echo(
                        f"{thread_color}--- Thread {thread_id} Output ---{reset_color}"
                    )
                    for buffered_line in buffer:
                        click.echo(f"{thread_color}{buffered_line}{reset_color}")
                    click.echo(f"{thread_color}------------------------{reset_color}")

        else:  # separate
            # 分离模式：将所有输出存储在线程特定的缓冲区中，在线程完成后输出
            for line in process.stdout:
                thread_outputs[thread_id].append(line.strip())

        process.wait()

        with output_lock:
            click.echo(
                f"{thread_color}Thread {thread_id} completed with return code: {process.returncode}{reset_color}"
            )

            # 如果是分离模式，在线程完成后输出所有内容
            if output_mode == "separate" and thread_outputs[thread_id]:
                click.echo(
                    f"{thread_color}=== Thread {thread_id} Complete Output ==={reset_color}"
                )
                for line in thread_outputs[thread_id]:
                    click.echo(f"{thread_color}{line}{reset_color}")
                click.echo(
                    f"{thread_color}================================={reset_color}"
                )

    # 创建并启动多个线程
    thread_list = []
    for i in range(threads):
        t = threading.Thread(target=run_tcpreplay, args=(base_cmd, i + 1))
        thread_list.append(t)
        t.start()

    # 等待所有线程完成
    for t in thread_list:
        t.join()

    if pps:
        click.echo(
            f"Successfully sent {pcap_file} with {pps} pps ({pps//threads} pps per thread) on {iface} using {threads} threads"
        )
    else:
        click.echo(
            f"Successfully sent {pcap_file} with {mbps} mbps ({mbps//threads} mbps per thread) on {iface} using {threads} threads"
        )


if __name__ == "__main__":
    cli()
