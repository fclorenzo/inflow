#!/usr/bin/env python3

import sys
import os
import argparse
from time import sleep

sys.path.append("utils") 

from mininet.net import Mininet
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.node import Switch, Host

# --- P4 Classes ---

class P4Host(Host):
    def config(self, **params):
        r = super(P4Host, self).config(**params)
        for off in ["rx", "tx", "sg"]:
            cmd = "/sbin/ethtool --offload %s %s off" % (self.defaultIntf(), off)
            self.cmd(cmd)
        self.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        self.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        self.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")
        return r

class P4Switch(Switch):
    def __init__(self, name, sw_path=None, json_path=None, 
                 thrift_port=None, grpc_port=None, **kwargs):
        Switch.__init__(self, name, **kwargs)
        self.sw_path = sw_path
        self.json_path = json_path
        self.thrift_port = thrift_port
        self.grpc_port = grpc_port
        self.logfile = '/tmp/p4s.{}.log'.format(self.name)

    def start(self, controllers):
        args = [self.sw_path]
        
        # --- 1. Switch Options (Must come BEFORE JSON) ---
        args.extend(['--device-id', str(self.dpid)])
        args.append("--log-console") # Moved UP
        if self.thrift_port:
            args.extend(['--thrift-port', str(self.thrift_port)])
        args.extend(['--cpu-port', '255'])
        
        for intf in self.intfs.values():
            if not intf.IP():
                port_index = self.ports[intf]
                args.extend(['-i', '{}@{}'.format(port_index, intf.name)])
        
        # --- 2. Positional Argument: JSON Config ---
        # This MUST be the last argument before the '--' separator
        args.append(self.json_path)
        
        # --- 3. P4Runtime Options (Must come AFTER --) ---
        if self.grpc_port:
            args.append("--") 
            args.append("--grpc-server-addr 0.0.0.0:{}".format(self.grpc_port))

        cmd_str = ' '.join(args) + ' > ' + self.logfile + ' 2>&1 &'
        print("\n" + "="*60)
        print(f"DEBUG: EXECUTION STRING FOR {self.name}:")
        print(cmd_str)
        print("="*60 + "\n")
        print("Starting P4Switch {}: {}".format(self.name, cmd_str))
        self.cmd(cmd_str)

    def stop(self):
        self.cmd('kill %' + self.sw_path)
        self.cmd('wait')
        super(P4Switch, self).stop()
# --- Main ---

def main():
    parser = argparse.ArgumentParser(description='InFlow Linear Topology')
    parser.add_argument('--behavioral-exe', help='Path to behavioral executable',
                        type=str, action='store', required=True)
    parser.add_argument('--json', help='Path to JSON config file',
                        type=str, action='store', required=True)
    args = parser.parse_args()

    setLogLevel('info')

    # Initialize Mininet without a topo object (we build it manually below)
    net = Mininet(topo=None, host=P4Host, switch=P4Switch, controller=None)
    
    # 1. Add Hosts
    h1 = net.addHost('h1', ip="10.0.1.1/24", mac="00:00:00:00:01:01")
    h2 = net.addHost('h2', ip="10.0.3.2/24", mac="00:00:00:00:03:02")
    
    # 2. Add Switches with distinct Thrift AND gRPC ports
    # S1: Thrift 9090, gRPC 9551
    s1 = net.addSwitch('s1', sw_path=args.behavioral_exe, json_path=args.json, 
                       thrift_port=9090, grpc_port=9551, dpid="0")
    
    # S2: Thrift 9091, gRPC 9552
    s2 = net.addSwitch('s2', sw_path=args.behavioral_exe, json_path=args.json, 
                       thrift_port=9091, grpc_port=9552, dpid="1")
    
    # S3: Thrift 9092, gRPC 9553
    s3 = net.addSwitch('s3', sw_path=args.behavioral_exe, json_path=args.json, 
                       thrift_port=9092, grpc_port=9553, dpid="2")
    
    # 3. Add Links
    net.addLink(h1, s1)
    net.addLink(s1, s2)
    net.addLink(s2, s3)
    net.addLink(s3, h2)
    
    # 4. Start Network
    net.start()
    print("--- Network Started ---")
    print("S1: Thrift 9090, gRPC 9551")
    print("S2: Thrift 9091, gRPC 9552")
    print("S3: Thrift 9092, gRPC 9553")

    # 5. Configure Hosts (Static ARP/Routes)
    h1.setARP("10.0.3.2", "00:00:00:00:03:02") 
    h2.setARP("10.0.1.1", "00:00:00:00:01:01")
    h1.setDefaultRoute("dev eth0")
    h2.setDefaultRoute("dev eth0")

    # 6. Open CLI
    CLI(net)
    net.stop()

if __name__ == '__main__':
    main()