#!/usr/bin/env python3

# The MIT License (MIT)
#
# Copyright (c) 2015 Chad Seaman
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import sys
import re
import string
from scapy.all import IP, UDP, DNS, DNSQR, sr1


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <target_ip>")
        sys.exit(1)

    target_ip = sys.argv[1]
    query = "_services._dns-sd._udp.local"
    replies = {}

    # Query the list of available services
    pkt = IP(dst=target_ip) / UDP(dport=5353) / DNS(rd=1, qd=DNSQR(qname=query, qtype='PTR'))
    ans = sr1(pkt, verbose=0, timeout=2)

    # Ignore timeouts or unreachable responses
    if ans is None or ans.haslayer('ICMP'):
        sys.exit(0)

    print(f"\n{target_ip} - START")
    print(f"[{query}]===")
    print(ans)
    print(f"[{query}]===")

    # Collect raw answer lines for parsing
    raw = str(ans).split('\n')
    services = []

    # Extract service types
    for entry in raw:
        cleaned = ''.join(ch for ch in entry if ch in string.printable)
        match = re.search(r'_[a-z_-]+', cleaned)
        if match:
            services.append(match.group(0))

    # Remove the initial query
    services = services[1:]
    replies[query] = len(ans)

    # Query each individual service
    for service in services:
        service_type = service.replace('_tcp', '') + '._tcp.local.'
        print(f"[{service_type}]===")

        pkt = IP(dst=target_ip) / UDP(dport=5353) / DNS(rd=1, qd=DNSQR(qname=service_type, qtype='PTR'))
        ans = sr1(pkt, verbose=0, timeout=2)

        print(ans)
        print(f"[{service_type}]===")

        if ans is not None:
            replies[service_type] = len(ans)

    # Output results
    print(replies)
    print(f"{target_ip} - END")


if __name__ == '__main__':
    main()
