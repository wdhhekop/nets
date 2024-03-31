from typing import List, Tuple

from prettytable import PrettyTable
import argparse
from scapy.all import sr1, traceroute
from scapy.layers.inet import IP, UDP
import socket
from ipwhois import IPWhois


def get_asn(ip: str) -> str:
    try:
        obj = IPWhois(ip)
        results = obj.lookup_rdap(depth=1)
        asn_description = results.get('asn_description', 'No AS Info')
    except Exception as e:
        asn_description = 'No AS Info'
    return asn_description


def get_additional_description(domain_info):
    if hasattr(domain_info, 'description') and domain_info.description:
        additional_description = "Description:", domain_info.description
    else:
        additional_description = "No Additional Description"
    return additional_description


def traceroute(dst: str, max_hops: int = 30, timeout: int = 1) -> List[Tuple[str, str]]:
    ip = socket.gethostbyname(dst)
    ttl = 1
    trace_list = []
    while True:
        p = IP(dst=ip, ttl=ttl) / UDP(dport=33434)
        reply = sr1(p, timeout=timeout, verbose=False)
        if reply:
            asn_info = get_asn(reply.src)
            trace_list.append((reply.src, asn_info))
            if reply.type == 3:
                break
        if ttl > max_hops:
            break
        ttl += 1
    asn_info = get_asn(ip)
    trace_list.append((ip, asn_info))
    return trace_list


def main():
    parser = argparse.ArgumentParser(description='Trace route to a host and display AS information for each hop.')
    parser.add_argument('destination', type=str, help='Destination host to trace route to (IP address or domain name)')

    args = parser.parse_args()
    dst = args.destination

    print(f"Tracing route to {dst}...\n")
    trace_info = traceroute(dst)

    table = PrettyTable()
    table.field_names = ["IP", "AS", "Country", "Description"]
    table.align["IP"] = "c"
    table.align["AS"] = "c"
    table.align["Country"] = "c"
    table.align["Description"] = "c"

    for ip, asn_info in trace_info:
        asn_info = asn_info.replace(',', '')
        asn = "AS" + asn_info.split()[0] if asn_info != "No AS Info" else ""
        country = asn_info.split()[1] if asn_info != "No AS Info" else ""
        description = " ".join(asn_info.split()[2:]) if asn_info != "No AS Info" else ""

        additional_description = get_additional_description(asn)
        if additional_description != "No Additional Description":
            description += f" ({additional_description})"

        table.add_row([ip, asn, country, description])

    print(table)


if __name__ == "__main__":
    main()
