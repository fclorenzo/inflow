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

def write_ipv4_rules(p4info_helper, ingress_sw, destination, dst_eth_addr, port):
    """
    Installs a rule in the ipv4_lpm table.
    """
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
    print(f"Installed IPv4 rule on {ingress_sw.name} for {destination}")

def write_inflow_tag_rule(p4info_helper, sw, ingress_port, conf, integ, auth):
    """
    Installs a tagging rule on the ingress switch.
    """
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
    """
    Installs a declassify rule on the egress switch.
    """
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
    """
    Installs simple L2 forwarding for ARP (Port 1 <-> Port 2).
    """
    # Port 1 -> 2
    entry1 = p4info_helper.buildTableEntry(
        table_name="InFlowIngress.l2_fwd",
        match_fields={"std_meta.ingress_port": 1},
        action_name="InFlowIngress.l2_forward",
        action_params={"port": 2}
    )
    sw.WriteTableEntry(entry1)

    # Port 2 -> 1
    entry2 = p4info_helper.buildTableEntry(
        table_name="InFlowIngress.l2_fwd",
        match_fields={"std_meta.ingress_port": 2},
        action_name="InFlowIngress.l2_forward",
        action_params={"port": 1}
    )
    sw.WriteTableEntry(entry2)
    print(f"Installed ARP rules on {sw.name}")

def calculate_auth_token(conf, integ, secret_key):
    """
    Calculates an 8-bit HMAC-SHA256 auth token.
    """
    # Pack the data into bytes (2 unsigned shorts)
    # '>' means Big Endian, 'H' means unsigned short (2 bytes)
    message = struct.pack('>HH', conf, integ)
    
    # Create the HMAC using SHA256
    # key must be bytes
    key_bytes = bytes(secret_key, 'utf-8')
    h = hmac.new(key_bytes, message, hashlib.sha256)
    
    # Get the digest
    digest = h.digest()
    
    # Take the first byte (8 bits) as our Auth Token
    # In a real system, you'd want more bits, but our P4 header is bit<8>
    return digest[0]

def main(p4info_file_path, bmv2_file_path):
    # Instantiate the P4Info helper
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # --- Create switch connections (USING CORRECT GRPC PORTS) ---
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:9551',  # Correct gRPC port
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')
        
        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s2',
            address='127.0.0.1:9552',  # Correct gRPC port
            device_id=1,
            proto_dump_file='logs/s2-p4runtime-requests.txt')

        s3 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s3',
            address='127.0.0.1:9553',  # Correct gRPC port
            device_id=2,
            proto_dump_file='logs/s3-p4runtime-requests.txt')

        # Send MasterArbitrationUpdate
        s1.MasterArbitrationUpdate()
        s2.MasterArbitrationUpdate()
        s3.MasterArbitrationUpdate()

        # Install the P4 program
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        s2.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        s3.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)

        print("--- P4 Pipeline Installed ---")

        # --- 1. Install ARP Rules ---
        write_arp_rules(p4info_helper, s1)
        write_arp_rules(p4info_helper, s2)
        write_arp_rules(p4info_helper, s3)

        # --- 2. Install IPv4 Routing ---
        # s1 routing
        write_ipv4_rules(p4info_helper, s1, "10.0.3.2", "00:00:00:00:03:02", 2)
        write_ipv4_rules(p4info_helper, s1, "10.0.1.1", "00:00:00:00:01:01", 1)
        
        # s2 routing
        write_ipv4_rules(p4info_helper, s2, "10.0.3.2", "00:00:00:00:03:02", 2)
        write_ipv4_rules(p4info_helper, s2, "10.0.1.1", "00:00:00:00:01:01", 1)

        # s3 routing
        write_ipv4_rules(p4info_helper, s3, "10.0.3.2", "00:00:00:00:03:02", 2)
        write_ipv4_rules(p4info_helper, s3, "10.0.1.1", "00:00:00:00:01:01", 1)

        # --- 3. Install InFlow Policies ---
        
        # Define a Secret Key (Known only to the Controller)
        SECRET_KEY = "MySuperSecretKey"

        # Define the policy we want to enforce
        # Example: Conf=1, Integ=1
        target_conf = 1
        target_integ = 1
        
        # Calculate the VALID token for this policy
        valid_auth = calculate_auth_token(target_conf, target_integ, SECRET_KEY)
        print(f"Calculated Auth Token for ({target_conf}, {target_integ}) is: {hex(valid_auth)}")

        # S1: Tag traffic from Host 1 with the calculated token
        write_inflow_tag_rule(p4info_helper, s1, ingress_port=1, 
                              conf=target_conf, integ=target_integ, auth=valid_auth)
        
        # S1: Declassify return traffic
        write_inflow_declassify_rule(p4info_helper, s1, ingress_port=2)

        # S3: Declassify traffic to Host 2
        write_inflow_declassify_rule(p4info_helper, s3, ingress_port=1)
        
        # S3: Tag return traffic from Host 2
        write_inflow_tag_rule(p4info_helper, s3, ingress_port=2, 
                              conf=target_conf, integ=target_integ, auth=valid_auth)

        print("--- All Rules Installed Successfully ---")

    except KeyboardInterrupt:
        print(" Shutting down.")
    except Exception as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    if not os.path.exists('logs'):
        os.mkdir('logs')
    
    # 1. MATCH THIS filename exactly with your compile command output
    # You ran: --p4runtime-files inflow.p4info.txtpb
    p4info_path = 'inflow.p4info.txtpb' 
    json_path = 'inflow.json'
    
    # 2. Verify files exist before trying to run
    if not os.path.exists(p4info_path):
        print(f"ERROR: Could not find P4Info file: {p4info_path}")
        print("Did you compile with: --p4runtime-files inflow.p4info.txtpb ?")
        sys.exit(1)
        
    if not os.path.exists(json_path):
        print(f"ERROR: Could not find JSON file: {json_path}")
        sys.exit(1)

    # 3. Run
    main(p4info_path, json_path)