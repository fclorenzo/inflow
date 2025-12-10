# InFlow: P4-Based Information Flow Control

**InFlow** is a Software Defined Networking (SDN) project that implements **Information Flow Control (IFC)** directly in the network data plane using P4.

Unlike traditional firewalls that filter based on IP addresses, InFlow enforces security policies based on **Confidentiality** and **Integrity** levels attached to the packet itself. It uses a custom cryptographic header and a P4Runtime controller to ensure that data can only flow between authorized endpoints, preventing data leaks and spoofing attacks.

## 🚀 Features

* **Custom P4 Protocol:** Implements a custom header (`ifc_t`) carrying security labels and cryptographic tokens.
  * **Dynamic SDN Controller:** A Python-based "Brain" that calculates HMAC tokens and pushes forwarding rules via **P4Runtime**.
  * **Cryptographic Enforcement:** Intermediate switches (Firewalls) verify packet integrity using HMAC-SHA256 (truncated) to prevent spoofing.
  * **Role-Based Switching:** The same P4 code allows switches to act as **Ingress** (Tagging), **Transit** (Verification), or **Egress** (Declassification) nodes based on Controller instructions.
  * **Attack Resistant:** Includes tools to simulate "Rogue Packet" injection and replay attacks to prove security.

-----

## 🏗️ Architecture

The project runs on a Mininet topology consisting of three P4-enabled switches (BMv2) arranged linearly:

`Host 1 <---> [S1: Ingress] <---> [S2: Transit] <---> [S3: Egress] <---> Host 2`

### 1\. The Data Plane (`inflow.p4`)

* **S1 (Ingress / Edge):** Receives standard IPv4 packets from Host 1. It encapsulates them with the **InFlow Header** containing the assigned Confidentiality/Integrity levels and a valid Auth Token.
  * **S2 (Transit / Firewall):** Inspects the InFlow header. It checks the **Auth Token** against a whitelist provided by the Controller. If the token is invalid (spoofed or wrong key), the packet is **dropped**.
  * **S3 (Egress / Edge):** Strips the InFlow header (Declassification) and forwards the original IPv4 packet to Host 2.

### 2\. The Control Plane (`controller.py`)

* Acts as the **Key Server**. It holds a secret key (unknown to the switches).
  * Calculates valid Auth Tokens: `Token = HMAC(Secret_Key, Conf_Level + Integ_Level)`.
  * Dynamically installs P4 table entries to:
    * Map Hosts to Security Levels.
      * Whitelist valid tokens on Transit switches.

-----

## 📦 Requirements

* **P4 Toolchain:** BMv2, PI, P4C (The standard P4 Tutorial VM environment is recommended).
  * **Python 3.8+**
  * **Mininet**

Install Python dependencies:

```bash
pip3 install -r requirements.txt
```

-----

## 🛠️ Usage

### 1\. Compile the P4 Program

The P4 code must be compiled for the BMv2 target. This generates the JSON pipeline and the P4Info helper file.

```bash
p4c-bm2-ss --p4v 16 -o inflow.json --p4runtime-files inflow.p4info.txtpb inflow.p4
```

### 2\. Start the Network Topology

This script starts Mininet, creates the virtual switches, and assigns them distinct gRPC ports (`9551`, `9552`, `9553`).

```bash
sudo python3 topo_line.py --behavioral-exe simple_switch_grpc --json inflow.json
```

*(Wait until you see the `mininet>` prompt).*

### 3\. Run the Controller (Admin Console)

Open a new terminal. This script connects to the switches and opens an interactive admin shell.

```bash
sudo python3 controller.py
```

-----

## 🎮 Admin Console Commands

Once the controller is running, you can manage the network dynamically:

| Command | Description |
| :--- | :--- |
| `policy <conf> <integ>` | Sets the security policy (e.g., `policy 1 1`). Calculates a new HMAC and pushes it to the network. |
| `firewall` | Activates the verification logic on Switch 2 (Transit). Until this is run, S2 acts as a standard forwarder. |
| `key <new_key>` | Rotates the Master Secret Key. Immediately invalidates old tokens (useful for thwarting replay attacks). |
| `exit` | Closes connections and exits. |

-----

## 🧪 Testing & Verification

### Test 1: Basic Connectivity

1. Start the network and controller.
2. Apply a policy: `admin@inflow> policy 1 1`
3. In Mininet, ping between hosts:

    ```bash
    mininet> h1 ping h2
    ```

    **Result:** Ping should succeed. The packet is being Tagged -\> Forwarded -\> Declassified automatically.

### Test 2: The Rogue Packet Attack

We verify that an attacker cannot forge a valid packet without the controller's secret key.

1. **Enable the Firewall:**

    ```bash
    admin@inflow> firewall
    ```

2. **Monitor the Output (S3):**
    Open a terminal and sniff the traffic leaving S2.

    ```bash
    sudo tcpdump -i s3-eth1 -n -e -v
    ```

3. **Launch Attack:**
    Run the rogue packet generator from Host 1 with a fake token (e.g., `0xAA`).

    ```bash
    mininet> h1 python3 rogue_packet.py 0xAA
    ```

    **Result:** The packet **will NOT appear** in the tcpdump. S2 dropped it because `0xAA` is not a valid HMAC for the current policy.

4. **Verify Valid Traffic:**
    Send a packet with the *correct* token (check your controller output for the current valid hex).

    ```bash
    mininet> h1 python3 rogue_packet.py 0x6f  # Replace 0x6f with actual token
    ```

    **Result:** The packet **appears** in tcpdump.

-----

## 📂 Repository Structure

* **`inflow.p4`**: The P4 source code defining headers, parsers, and the ingress pipeline.
  * **`controller.py`**: The P4Runtime Control Plane script (Admin Console).
  * **`topo_line.py`**: The Mininet topology script that sets up the environment.
  * **`rogue_packet.py`**: Scapy script for generating spoofed packets for security testing.
  * **`inflow.json` / `inflow.p4info.txtpb`**: Compiled artifacts required by the switch.
  * **`utils/`**: Helper libraries for P4Runtime interactions.
