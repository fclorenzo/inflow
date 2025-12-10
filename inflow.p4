/*
 * InFlow: Phase 1 - Core Data Plane Skeleton
 * Target: BMv2 V1Model
 */
#include <core.p4>
#include <v1model.p4> // Standard V1Model architecture definitions [cite: 707]

// --- 1. Header Definitions ---

// Custom EtherType for InFlow.
// We use 0x88B5, which is in the "Experimental" range.
const bit<16> ETHERTYPE_INFLOW = 0x88B5;
const bit<16> ETHERTYPE_IPV4   = 0x0800;

// Standard Ethernet
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

// The 'InFlow' header, as per your article [cite: 3542-3543]
header ifc_t {
    bit<16> conf_mask;
    bit<16> integ_mask;
    bit<8>  auth;
}

// Standard IPv4
header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

// Struct containing all headers our switch will process
struct headers_t {
    ethernet_t eth;
    ifc_t      ifc;  // InFlow header
    ipv4_t     ipv4; // Payload
}

// We can add fields here for Phase 2
struct metadata_t {
    bit<1> verify_auth; // 1 = Check Auth, 0 = Don't Check
}

// --- 2. Parser Definition ---

parser InFlowParser(packet_in packet,
                    out headers_t hdr,
                    inout metadata_t meta,
                    inout standard_metadata_t std_meta) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.eth);
        // Decide where to go based on EtherType
        transition select(hdr.eth.etherType) {
            ETHERTYPE_INFLOW: parse_ifc;
            ETHERTYPE_IPV4:   parse_ipv4;
            default:          accept;
        }
    }

    // This state is entered if the EtherType matches ETHERTYPE_INFLOW
    state parse_ifc {
        packet.extract(hdr.ifc);
        // After InFlow, we assume an IPv4 payload
        // This is a design decision.
        transition parse_ipv4;
    }

    // This state is entered for standard IPv4 or after parsing InFlow
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

    //state accept {
        /* End of parsing */
    //}
}

// --- 3. Ingress Control (Phase 2) ---

control InFlowIngress(inout headers_t hdr,
                      inout metadata_t meta,
                      inout standard_metadata_t std_meta) {

    // --- Actions ---

    action drop() {
        mark_to_drop(std_meta);
    }

    action ipv4_forward(bit<48> dstAddr, bit<9> port) {
        hdr.eth.srcAddr = hdr.eth.dstAddr;
        hdr.eth.dstAddr = dstAddr;
        std_meta.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action l2_forward(bit<9> port) {
        std_meta.egress_spec = port;
    }

    // ACTION: Tagging (Source Domain / S1)
    action inflow_tag(bit<16> conf, bit<16> integ, bit<8> auth) {
        hdr.ifc.setValid();
        hdr.ifc.conf_mask = conf;
        hdr.ifc.integ_mask = integ;
        hdr.ifc.auth = auth;
        hdr.eth.etherType = ETHERTYPE_INFLOW;
    }

    // ACTION: Declassification (Destination Domain / S3)
    action inflow_declassify() {
        hdr.ifc.setInvalid();
        hdr.eth.etherType = ETHERTYPE_IPV4;
    }
    
    // --- NEW ACTIONS FOR PHASE 5 ---

// ACTION: Transit Check (Triggered by S2)
    // Old way: auth_check.apply();  <-- CAUSED ERROR
    // New way: Set the flag
    action inflow_transit() {
        meta.verify_auth = 1;
    }

    // ACTION: Auth Match (Used when token is valid)
    // If the table finds a match, we do nothing (allow packet).
    action auth_match() {
        // No-op: Packet is safe.
    }

    // --- Tables ---

    table ipv4_lpm {
        key = { hdr.ipv4.dstAddr: lpm; }
        actions = { ipv4_forward; drop; NoAction; }
        size = 1024;
        default_action = drop();
    }

    // This handles Tagging and Declassifying
    table inflow_op {
        key = { std_meta.ingress_port: exact; }
        actions = { inflow_tag; inflow_declassify; inflow_transit; NoAction; }
        size = 1024;
        default_action = NoAction();
    }

    table l2_fwd {
        key = { std_meta.ingress_port: exact; }
        actions = { l2_forward; drop; }
        size = 1024;
        default_action = drop();
    }

    // --- NEW TABLE FOR PHASE 5 ---
    // The Firewall Table
    // Matches specific (Conf + Integ + Auth) combinations.
    // If a packet has a token that isn't in this table -> DROP.
    table auth_check {
        key = {
            hdr.ifc.conf_mask: exact;
            hdr.ifc.integ_mask: exact;
            hdr.ifc.auth: exact;
        }
        actions = { auth_match; drop; }
        size = 1024;
        default_action = drop();
    }

// --- Pipeline Logic ---
    apply {
        if (hdr.ipv4.isValid()) {
            // 1. Security Operations
            // This might run 'inflow_transit', which sets meta.verify_auth = 1
            inflow_op.apply();

            // 2. Check if we need to verify authentication
            if (meta.verify_auth == 1) {
                auth_check.apply();
            }
            
            // 3. Routing
            ipv4_lpm.apply();
        } 
        else if (hdr.eth.etherType == 0x0806) {
            l2_fwd.apply();
        }
    }
}

// --- 4. Egress Control (Phase 2) ---

// This is the "Egress Match-Action Pipeline" [cite: 38, 92]
control InFlowEgress(inout headers_t hdr,
                     inout metadata_t meta,
                     inout standard_metadata_t std_meta) {
    apply {
        // Empty for Phase 1.
    }
}

// --- 5. Deparser Definition ---

// Reconstructs the packet before it's sent out [cite: 47, 96]
control InFlowDeparser(packet_out packet, in headers_t hdr) {
    apply {
        // We must emit headers in the correct order
        // and only if they are valid (i.e., were parsed)
        packet.emit(hdr.eth);
        packet.emit(hdr.ifc); // Emits if hdr.ifc.isValid() is true
        packet.emit(hdr.ipv4);
    }
}

// --- 6. Checksum Controls ---
control InFlowVerifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply {
        // Verify IPv4 Checksum
        verify_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

control InFlowComputeChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply {
        // Recalculate IPv4 Checksum
        // This is required because we modified the TTL in Ingress
        update_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

// --- 7. Switch Instantiation ---

// This connects all the programmable blocks [cite: 82]
V1Switch(
    InFlowParser(),
    InFlowVerifyChecksum(),
    InFlowIngress(),
    InFlowEgress(),
    InFlowComputeChecksum(),
    InFlowDeparser()
) main;