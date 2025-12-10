#!/usr/bin/env python3
import sys
from scapy.all import *

# 1. Define the Custom InFlow Header
# This teaches Scapy how to build our custom protocol
class InFlow(Packet):
    name = "InFlow"
    fields_desc = [
        ShortField("conf_mask", 0),
        ShortField("integ_mask", 0),
        ByteField("auth", 0)
    ]

# Bind InFlow header to Ethernet (EtherType 0x88B5)
bind_layers(Ether, InFlow, type=0x88B5)
# Bind IP header to InFlow (so it looks like a real tunnel)
bind_layers(InFlow, IP)

def main():
    if len(sys.argv) < 2:
        print("Usage: ./rogue_packet.py <fake_auth_hex>")
        print("Example: ./rogue_packet.py 0xAA")
        sys.exit(1)

    # User input for the Fake Token
    fake_token = int(sys.argv[1], 16)
    
    print(f"😈 Generating Rogue Packet with Fake Auth Token: {hex(fake_token)}...")

    # 2. Craft the Malicious Packet
    # Ether: Destined for S2 (simulate a tagged packet on the wire)
    # InFlow: Conf=1, Integ=1, AUTH=FAKE!
    # IP: Normal ICMP Ping
    pkt = Ether(src="00:00:00:00:01:01", dst="00:00:00:00:02:01", type=0x88B5) / \
          InFlow(conf_mask=1, integ_mask=1, auth=fake_token) / \
          IP(src="10.0.1.1", dst="10.0.3.2") / \
          ICMP()

    # 3. Inject it into the network
    # We send it out of h1's interface
    sendp(pkt, iface="h1-eth0", verbose=True)
    print("🚀 Packet sent!")

if __name__ == "__main__":
    main()