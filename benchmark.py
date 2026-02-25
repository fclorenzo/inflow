#!/usr/bin/env python3
import sys
import os
import time
import csv
import re
import matplotlib.pyplot as plt
import subprocess

# Mininet imports
from mininet.net import Mininet
from mininet.log import setLogLevel
from topo_line import P4Host, P4Switch

# P4Runtime imports
sys.path.append("utils")
import p4runtime_lib.bmv2
import p4runtime_lib.helper
from controller import install_static_rules, apply_policy, enable_firewall
from p4runtime_lib.switch import ShutdownAllSwitchConnections

benchmark_dir = "benchmark_results"

def parse_ping(output):
    """Parses mininet ping output to get average latency."""
    match = re.search(r'rtt min/avg/max/mdev = [\d\.]+/(.*?)/[\d\.]+/', output)
    if match:
        return float(match.group(1))
    return None

def parse_iperf(output):
    """Parses iperf output to get bandwidth in Mbits/sec."""
    # iperf format usually ends with e.g., "  1.23 Mbits/sec"
    matches = re.findall(r'(\d+\.?\d*)\s+Mbits/sec', output)
    if matches:
        return float(matches[-1]) # Return the last match (the summary)
    return None

def run_tests(net, phase, sizes):
    print(f"\n--- Starting {phase} Tests ---")
    h1 = net.get('h1')
    h2 = net.get('h2')
    
    results = {}
    
    for size in sizes:
        print(f"Testing Packet Size: {size} Bytes...")
        
        # 1. Latency Test (Ping)
        # We send 10 pings to get a stable average
        ping_out = h1.cmd(f'ping -c 10 -s {size} {h2.IP()}')
        latency = parse_ping(ping_out)
        
        # 2. Throughput Test (iPerf)
        # Start iPerf server on h2, run client on h1 (UDP mode to force specific packet sizes)
        h2.cmd('iperf -s -u &')
        time.sleep(1) # Let server start
        iperf_out = h1.cmd(f'iperf -c {h2.IP()} -u -b 100M -l {size} -t 5')
        h2.cmd('kill %iperf') # Stop server
        throughput = parse_iperf(iperf_out)
        
        results[size] = {'latency': latency, 'throughput': throughput}
        print(f"  Result -> Latency: {latency} ms | Throughput: {throughput} Mbps")
        
    return results

def plot_and_save(baseline, inflow, sizes):
    print("\n--- Generating Graphs and CSV ---")
    
    # 1. Save CSV
    with open(os.path.join(benchmark_dir, 'benchmark_results.csv'), 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Phase', 'Size (Bytes)', 'Latency (ms)', 'Throughput (Mbps)'])
        for s in sizes:
            writer.writerow(['Baseline', s, baseline[s]['latency'], baseline[s]['throughput']])
            writer.writerow(['InFlow', s, inflow[s]['latency'], inflow[s]['throughput']])
    print("Saved 'benchmark_results.csv'")

    # 2. Plot Latency
    plt.figure(figsize=(8, 5))
    bl_lat = [baseline[s]['latency'] for s in sizes]
    if_lat = [inflow[s]['latency'] for s in sizes]
    plt.plot(sizes, bl_lat, marker='o', label='Baseline (No Security)')
    plt.plot(sizes, if_lat, marker='s', label='InFlow (Tag+Verify+Declassify)')
    plt.xlabel('Packet Size (Bytes)')
    plt.ylabel('Average Latency (ms)')
    plt.title('Network Latency Comparison')
    plt.grid(True)
    plt.legend()
    plt.savefig(os.path.join(benchmark_dir, 'latency_comparison.png'))
    print("Saved 'latency_comparison.png'")

    # 3. Plot Throughput
    plt.figure(figsize=(8, 5))
    bl_tp = [baseline[s]['throughput'] for s in sizes]
    if_tp = [inflow[s]['throughput'] for s in sizes]
    plt.plot(sizes, bl_tp, marker='o', label='Baseline')
    plt.plot(sizes, if_tp, marker='s', label='InFlow')
    plt.xlabel('Packet Size (Bytes)')
    plt.ylabel('Throughput (Mbps)')
    plt.title('Network Throughput Comparison (UDP)')
    plt.grid(True)
    plt.legend()
    plt.savefig(os.path.join(benchmark_dir, '/throughput_comparison.png'))
    print("Saved 'throughput_comparison.png'")
    time.sleep(1)

def cleanup_mininet():
    print("--- Cleaning up leftover Mininet processes ---")
    # 'mn -c' cleans up mininet network namespaces and virtual interfaces
    subprocess.run(['sudo', 'mn', '-c'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # Aggressively kill any lingering P4 switches or iperf servers just in case
    subprocess.run(['sudo', 'killall', '-9', 'simple_switch_grpc'], stderr=subprocess.DEVNULL)
    subprocess.run(['sudo', 'killall', '-9', 'iperf'], stderr=subprocess.DEVNULL)
    
    time.sleep(2) # Give the system a moment to fully clear the resources

def main():
    setLogLevel('error') # Keep mininet quiet so we can see our logs
    sizes = [64, 128, 256, 512, 1024]
    
    # Paths to compiled P4 files
    p4info_path = 'inflow.p4info.txtpb'
    json_path = 'inflow.json'
    bmv2_exe = 'simple_switch_grpc'
    
    if not os.path.exists(json_path):
        print("Error: Compile inflow.p4 first!")
        sys.exit(1)

    # Create the folder if it doesn't already exist
    if not os.path.exists(benchmark_dir):
        os.makedirs(benchmark_dir)

    # 1. Start Network Topology
    print("Starting Mininet Topology...")
    net = Mininet(topo=None, host=P4Host, switch=P4Switch, controller=None)
    h1 = net.addHost('h1', ip="10.0.1.1/24", mac="00:00:00:00:01:01")
    h2 = net.addHost('h2', ip="10.0.3.2/24", mac="00:00:00:00:03:02")
    
    s1 = net.addSwitch('s1', sw_path=bmv2_exe, json_path=json_path, thrift_port=9090, grpc_port=9551, dpid="0")
    s2 = net.addSwitch('s2', sw_path=bmv2_exe, json_path=json_path, thrift_port=9091, grpc_port=9552, dpid="1")
    s3 = net.addSwitch('s3', sw_path=bmv2_exe, json_path=json_path, thrift_port=9092, grpc_port=9553, dpid="2")
    
    net.addLink(h1, s1)
    net.addLink(s1, s2)
    net.addLink(s2, s3)
    net.addLink(s3, h2)
    
    net.start()
    h1.setARP("10.0.3.2", "00:00:00:00:03:02") 
    h2.setARP("10.0.1.1", "00:00:00:00:01:01")
    h1.setDefaultRoute("dev h1-eth0")
    h2.setDefaultRoute("dev h2-eth0")
    time.sleep(2)

    # 2. Connect to Control Plane
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_path)
    s1_conn = p4runtime_lib.bmv2.Bmv2SwitchConnection('s1', address='127.0.0.1:9551', device_id=0)
    s2_conn = p4runtime_lib.bmv2.Bmv2SwitchConnection('s2', address='127.0.0.1:9552', device_id=1)
    s3_conn = p4runtime_lib.bmv2.Bmv2SwitchConnection('s3', address='127.0.0.1:9553', device_id=2)

    for sw in [s1_conn, s2_conn, s3_conn]:
        sw.MasterArbitrationUpdate()
        sw.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=json_path)

    # 3. Setup Baseline (Basic routing, no InFlow security)
    install_static_rules(p4info_helper, s1_conn, s2_conn, s3_conn)
    time.sleep(1)
    
    # 4. Run Baseline Tests
    baseline_results = run_tests(net, 'Baseline', sizes)

    # 5. Enable InFlow
    print("\n--- Applying InFlow Security Policies ---")
    apply_policy(p4info_helper, s1_conn, s2_conn, s3_conn, conf=1, integ=1, secret_key="BenchmarkKey")
    enable_firewall(p4info_helper, s2_conn)
    time.sleep(1)

    # 6. Run InFlow Tests
    inflow_results = run_tests(net, 'InFlow', sizes)

    # 7. Cleanup & Generate Results
    ShutdownAllSwitchConnections()
    net.stop()
    
    plot_and_save(baseline_results, inflow_results, sizes)
    print("\n✅ Benchmarking Complete!")

if __name__ == '__main__':
    # Make sure we run as root
    if os.geteuid() != 0:
        print("Please run as root (sudo python3 benchmark.py)")
        sys.exit(1)
    main()