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
    // Empty for now
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

// --- 3. Ingress Control (Phase 2 Implementation) ---

control InFlowIngress(inout headers_t hdr,
                      inout metadata_t meta,
                      inout standard_metadata_t std_meta) {

    // --- Actions ---

    action drop() {
        mark_to_drop(std_meta);
    }

    // Standard IPv4 forwarding action [cite: 2808, 1431]
    action ipv4_forward(bit<48> dstAddr, bit<9> port) {
        // Update DMAC/SMAC (simplified for this lab)
        hdr.eth.srcAddr = hdr.eth.dstAddr; 
        hdr.eth.dstAddr = dstAddr;
        
        // Set egress port
        std_meta.egress_spec = port;
        
        // Decrement TTL
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    // Action: Simple L2 Forwarding (for ARP)
    action l2_forward(bit<9> port) {
        std_meta.egress_spec = port;
    }

    // ACTION: Tagging (Source Domain / S1)
    // Adds the IFC header and sets the initial masks
    action inflow_tag(bit<16> conf, bit<16> integ, bit<8> auth) {
        // 1. Validate the header
        hdr.ifc.setValid();
        
        // 2. Set the data
        hdr.ifc.conf_mask = conf;
        hdr.ifc.integ_mask = integ;
        hdr.ifc.auth = auth;

        // 3. Update EtherType to indicate this is now an InFlow packet
        // The parser will see this on the NEXT switch
        hdr.eth.etherType = ETHERTYPE_INFLOW;
    }

    // ACTION: Declassification (Destination Domain / S3)
    // Removes the IFC header
    action inflow_declassify() {
        // We don't need to check if it is valid. 
        // If it is valid, this makes it invalid.
        // If it is already invalid, it stays invalid (no-op).
        hdr.ifc.setInvalid();
            
        // Restore EtherType to standard IPv4
        // This ensures the next hop interprets the payload correctly
        hdr.eth.etherType = ETHERTYPE_IPV4;
    }
    
    // ACTION: Transit (No-Op for now, just validation in future)
    action inflow_transit() {
        // In the future, we will check Auth here.
        // For now, we just let it pass.
    }

    // --- Tables ---

    // Table 1: Routing
    // Matches Destination IP -> Output Port
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    // Table 2: Security Operations
    // Matches Ingress Port -> Security Action (Tag/Declassify)
    // This allows the Controller to tell S1 "Tag packets coming from Host 1"
    table inflow_op {
        key = {
            std_meta.ingress_port: exact;
        }
        actions = {
            inflow_tag;
            inflow_declassify;
            inflow_transit;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    // New Table: Handle ARP (and other L2 broadcast)
    table l2_fwd {
        key = {
            std_meta.ingress_port: exact;
        }
        actions = {
            l2_forward;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    // --- Pipeline Logic ---
    apply {
        // Check if it is an IPv4 packet (or InFlow-encapsulated IPv4)
        if (hdr.ipv4.isValid()) {
            // 1. Security Operations
            inflow_op.apply();
            // 2. Routing
            ipv4_lpm.apply();
        } 
        // If NOT IPv4, check if it is ARP (0x0806)
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