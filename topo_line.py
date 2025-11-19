#!/usr/bin/env python3

import sys
import os
import argparse
from time import sleep

sys.path.append("utils") 

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI

# These classes are standard in the P4 tutorial VM environment
# If you get an import error, ensure p4_mininet.py is in your path
from p4_mininet import P4Switch, P4Host

class LinearInFlowTopo(Topo):
    """
    Linear Topology for InFlow:
    h1 <--> s1 <--> s2 <--> s3 <--> h2
    """
    def __init__(self, sw_path, json_path, **opts):
        Topo.__init__(self, **opts)

        # --- Add Hosts ---
        # We assign static IPs and MACs to simplify debugging
        h1 = self.addHost('h1', ip="10.0.1.1/24", mac="00:00:00:00:01:01")
        h2 = self.addHost('h2', ip="10.0.3.2/24", mac="00:00:00:00:03:02")

        # --- Add P4 Switches ---
        # s1: The "Ingress" (Tagging) Switch
        s1 = self.addSwitch('s1',
                            sw_path=sw_path,
                            json_path=json_path,
                            thrift_port=9090) # Default Thrift port

        # s2: The "Transit" (Tag Update) Switch
        s2 = self.addSwitch('s2',
                            sw_path=sw_path,
                            json_path=json_path,
                            thrift_port=9091) # Increment port

        # s3: The "Egress" (Declassification) Switch
        s3 = self.addSwitch('s3',
                            sw_path=sw_path,
                            json_path=json_path,
                            thrift_port=9092) # Increment port

        # --- Add Links ---
        # Wiring them in a line
        self.addLink(h1, s1) # s1-eth1 connects to h1
        self.addLink(s1, s2) # s1-eth2 connects to s2-eth2 (usually)
        self.addLink(s2, s3)
        self.addLink(s3, h2)

def main():
    parser = argparse.ArgumentParser(description='InFlow Linear Topology')
    parser.add_argument('--behavioral-exe', help='Path to behavioral executable',
                        type=str, action='store', required=True)
    parser.add_argument('--json', help='Path to JSON config file',
                        type=str, action='store', required=True)
    args = parser.parse_args()

    setLogLevel('info')

    topo = LinearInFlowTopo(args.behavioral_exe, args.json)
    
    # We disable the controller because we are using static rules/P4 logic
    # strictly for the data plane development right now.
    net = Mininet(topo=topo,
                  host=P4Host,
                  switch=P4Switch,
                  controller=None) 

    net.start()

    print("--- Network Started ---")
    print("Topology: h1 <-> s1 <-> s2 <-> s3 <-> h2")
    print("You can now use the Mininet CLI.")
    print("Note: Pings will FAIL until we program the switch logic in the next phase.")
    
    # Helper to configure host interfaces (ARP/Routes) statically
    h1 = net.get('h1')
    h2 = net.get('h2')
    h1.setARP("10.0.3.2", "00:00:00:00:03:02") # Tell h1 where h2 is
    h2.setARP("10.0.1.1", "00:00:00:00:01:01") # Tell h2 where h1 is
    h1.setDefaultRoute("dev eth0")
    h2.setDefaultRoute("dev eth0")

    CLI(net)
    net.stop()

if __name__ == '__main__':
    main()