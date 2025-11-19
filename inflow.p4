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

// This is the "Ingress Match-Action Pipeline" [cite: 35, 90]
// We will add all the InFlow logic (auth, policy) here in the next phase.
control InFlowIngress(inout headers_t hdr,
                      inout metadata_t meta,
                      inout standard_metadata_t std_meta) {
    apply {
        // Empty for Phase 1.
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
// V1Model requires these controls [cite: 87, 94]

control InFlowVerifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply {
        // Verification is left empty for this skeleton
    }
}

control InFlowComputeChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply {
        // Computation is left empty for this skeleton
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