from typing import List, Tuple

from prettytable import PrettyTable
import argparse
from scapy.all import sr1
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


def custom_traceroute(dst: str, max_hops: int = 30, timeout: int = 1) -> List[Tuple[str, str]]:
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
    trace_info = custom_traceroute(dst)

    table = PrettyTable()
    table.field_names = ["IP", "AS", "Country", "Description"]
    table.align["IP"] = "c"
    table.align["AS"] = "c"
    table.align["Country"] = "c"
    table.align["Description"] = "c"

    for ip, asn_info in trace_info:
        asn_info_parts = asn_info.replace(',', '').split()
        asn = "AS" + asn_info_parts[0] if len(asn_info_parts) > 0 else ""
        country = asn_info_parts[1] if len(asn_info_parts) > 1 else ""
        description = " ".join(asn_info_parts[2:]) if len(asn_info_parts) > 2 else ""

        table.add_row([ip, asn, country, description])

    print(table)


if __name__ == "__main__":
    main()
