#!/usr/bin/env python3

import sys
import os
import hmac
import hashlib
import struct

# Add the utils folder to the path so we can import the libraries
sys.path.append("utils")

import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections

# --- Helper Functions (P4Runtime Interactions) ---

def write_inflow_transit_rule(p4info_helper, sw, ingress_port):
    """
    Tells the switch to run the 'inflow_transit' action (Firewall check)
    instead of just forwarding blindly.
    """
    table_entry = p4info_helper.buildTableEntry(
        table_name="InFlowIngress.inflow_op",
        match_fields={
            "std_meta.ingress_port": ingress_port
        },
        action_name="InFlowIngress.inflow_transit",
        action_params={}
    )
    sw.WriteTableEntry(table_entry)
    print(f"Installed TRANSIT (Firewall) rule on {sw.name} port {ingress_port}")

def write_auth_check_rule(p4info_helper, sw, conf, integ, auth):
    """
    Whitelists a specific (Conf, Integ, Auth) combination.
    """
    table_entry = p4info_helper.buildTableEntry(
        table_name="InFlowIngress.auth_check",
        match_fields={
            "hdr.ifc.conf_mask": conf,
            "hdr.ifc.integ_mask": integ,
            "hdr.ifc.auth": auth
        },
        action_name="InFlowIngress.auth_match",
        action_params={}
    )
    sw.WriteTableEntry(table_entry)
    print(f"Installed AUTH CHECK for Token {hex(auth)} on {sw.name}")

def write_ipv4_rules(p4info_helper, ingress_sw, destination, dst_eth_addr, port):
    """Installs IPv4 forwarding rules."""
    table_entry = p4info_helper.buildTableEntry(
        table_name="InFlowIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": (destination, 32)
        },
        action_name="InFlowIngress.ipv4_forward",
        action_params={
            "dstAddr": dst_eth_addr,
            "port": port
        }
    )
    ingress_sw.WriteTableEntry(table_entry)
    # print(f"Installed IPv4 rule on {ingress_sw.name} for {destination}")

def write_inflow_tag_rule(p4info_helper, sw, ingress_port, conf, integ, auth):
    """Installs a tagging rule (Ingress)."""
    table_entry = p4info_helper.buildTableEntry(
        table_name="InFlowIngress.inflow_op",
        match_fields={
            "std_meta.ingress_port": ingress_port
        },
        action_name="InFlowIngress.inflow_tag",
        action_params={
            "conf": conf,
            "integ": integ,
            "auth": auth
        }
    )
    sw.WriteTableEntry(table_entry)
    print(f"Installed TAG rule on {sw.name} port {ingress_port}")

def write_inflow_declassify_rule(p4info_helper, sw, ingress_port):
    """Installs a declassify rule (Egress)."""
    table_entry = p4info_helper.buildTableEntry(
        table_name="InFlowIngress.inflow_op",
        match_fields={
            "std_meta.ingress_port": ingress_port
        },
        action_name="InFlowIngress.inflow_declassify",
        action_params={}
    )
    sw.WriteTableEntry(table_entry)
    print(f"Installed DECLASSIFY rule on {sw.name} port {ingress_port}")

def write_arp_rules(p4info_helper, sw):
    """Installs simple L2 forwarding for ARP."""
    for port_in, port_out in [(1, 2), (2, 1)]:
        entry = p4info_helper.buildTableEntry(
            table_name="InFlowIngress.l2_fwd",
            match_fields={"std_meta.ingress_port": port_in},
            action_name="InFlowIngress.l2_forward",
            action_params={"port": port_out}
        )
        sw.WriteTableEntry(entry)

def calculate_auth_token(conf, integ, secret_key):
    """Calculates an 8-bit HMAC-SHA256 auth token."""
    message = struct.pack('>HH', conf, integ)
    key_bytes = bytes(secret_key, 'utf-8')
    h = hmac.new(key_bytes, message, hashlib.sha256)
    return h.digest()[0]

# --- Admin Logic ---

def install_static_rules(p4info_helper, s1, s2, s3):
    """Sets up the base connectivity (ARP, IPv4)."""
    print("--- Installing Static Connectivity Rules ---")
    for sw in [s1, s2, s3]:
        write_arp_rules(p4info_helper, sw)
    
    # Simple Linear Routing: 1 <-> 2
    # In a real 5000-switch net, this would be a loop or algorithm (OSPF/BGP)
    for sw in [s1, s2, s3]:
        write_ipv4_rules(p4info_helper, sw, "10.0.3.2", "00:00:00:00:03:02", 2)
        write_ipv4_rules(p4info_helper, sw, "10.0.1.1", "00:00:00:00:01:01", 1)

def apply_policy(p4info_helper, s1, s2, s3, conf, integ, secret_key):
    """
    The 'Brain': Calculates the token and pushes it to Edge and Core switches.
    """
    # 1. Calculate HMAC
    auth_token = calculate_auth_token(conf, integ, secret_key)
    print(f"\n[ADMIN] New Policy: Conf={conf}, Integ={integ}")
    print(f"[ADMIN] Calculated HMAC Token: {hex(auth_token)}")

    # 2. Update Edge Switches (Tagging)
    # S1 tags traffic entering from Host 1
    write_inflow_tag_rule(p4info_helper, s1, ingress_port=1, 
                          conf=conf, integ=integ, auth=auth_token)
    # S3 tags traffic entering from Host 2
    write_inflow_tag_rule(p4info_helper, s3, ingress_port=2, 
                          conf=conf, integ=integ, auth=auth_token)

    # 3. Update Edge Switches (Declassification - Always on)
    write_inflow_declassify_rule(p4info_helper, s1, ingress_port=2)
    write_inflow_declassify_rule(p4info_helper, s3, ingress_port=1)

    # 4. Update Core/Firewall Switches (Verification)
    # We update the whitelist on S2 to accept this new token
    write_auth_check_rule(p4info_helper, s2, conf, integ, auth_token)

def enable_firewall(p4info_helper, s2):
    """Activates the 'Check' logic on the middle switch."""
    print("\n[ADMIN] Activating Firewall Logic on S2...")
    write_inflow_transit_rule(p4info_helper, s2, ingress_port=1)
    write_inflow_transit_rule(p4info_helper, s2, ingress_port=2)

def main(p4info_file_path, bmv2_file_path):
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # --- Connect to Switches ---
        print("Connecting to switches...")
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1', address='127.0.0.1:9551', device_id=0,
            proto_dump_file='logs/s1.log')
        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s2', address='127.0.0.1:9552', device_id=1,
            proto_dump_file='logs/s2.log')
        s3 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s3', address='127.0.0.1:9553', device_id=2,
            proto_dump_file='logs/s3.log')

        for sw in [s1, s2, s3]:
            sw.MasterArbitrationUpdate()
            sw.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                           bmv2_json_file_path=bmv2_file_path)

        # --- Initial Setup ---
        install_static_rules(p4info_helper, s1, s2, s3)
        
        # Default Secret Key
        SECRET_KEY = "MySuperSecretKey"
        
        # --- Interactive Menu ---
        print("\n" + "="*40)
        print(" InFlow Controller (Admin Console)")
        print("="*40)
        print("Network is ready. Static routes installed.")
        
        while True:
            print("\nAvailable Commands:")
            print("  1. policy <conf> <integ>  (Push new security level)")
            print("  2. firewall               (Turn S2 into a firewall)")
            print("  3. key <new_key>          (Rotate Secret Key)")
            print("  4. exit")
            
            cmd_raw = input("\nadmin@inflow> ").strip()
            cmd = cmd_raw.split()
            
            if not cmd: continue
            
            if cmd[0] == "exit":
                print("Exiting controller...")
                break
            
            elif cmd[0] == "policy":
                if len(cmd) != 3:
                    print("Usage: policy <conf_level> <integ_level>")
                    continue
                try:
                    c = int(cmd[1])
                    i = int(cmd[2])
                    apply_policy(p4info_helper, s1, s2, s3, c, i, SECRET_KEY)
                    print("[SUCCESS] Policy pushed to network.")
                except ValueError:
                    print("Error: Levels must be integers.")

            elif cmd[0] == "firewall":
                enable_firewall(p4info_helper, s2)
                print("[SUCCESS] S2 is now verifying Auth Tokens.")

            elif cmd[0] == "key":
                if len(cmd) < 2:
                    print("Usage: key <new_secret_string>")
                    continue
                SECRET_KEY = cmd[1]
                print(f"[ADMIN] Secret Key rotated! New key: {SECRET_KEY}")
                print("[!] IMPORTANT: Run 'policy' again to push new tokens!")
                
            else:
                print("Unknown command.")

    except KeyboardInterrupt:
        print(" Shutting down.")
    except Exception as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    if not os.path.exists('logs'): os.mkdir('logs')
    # Strict file checking
    p4info_path = 'inflow.p4info.txtpb' 
    json_path = 'inflow.json'
    if not os.path.exists(p4info_path) or not os.path.exists(json_path):
        print("Error: Compile P4 first!")
        sys.exit(1)
    main(p4info_path, json_path)