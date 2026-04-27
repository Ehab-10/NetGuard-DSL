# Access Policy DSL - Engineering Documentation

## 1. Project Overview
This project implements a Domain-Specific Language (DSL) that allows network administrators to define access intent in a clean, human-readable text format. The system parses this intent and compiles it into various network configurations, including Cisco ACLs, and Linux firewall rule sets (iptables and nftables). 

Additionally, it provides a comprehensive validation and simulation engine to detect misconfigurations, ensuring a DHCP/DNS-aware security design before deployment.

## 2. Architecture
The project is built using Python and consists of the following core modules:
- **Parser (`parser.py`)**: Uses the `Lark` library to define the grammar and parse the DSL into an Abstract Syntax Tree (AST).
- **Model Builder (`model.py`)**: Converts the AST into an intermediate structured dictionary (JSON-friendly format) representing roles, networks, services, and rules.
- **Rule Compilers**: Translates the intermediate model into device-specific syntax.
  - `compiler_acl.py`: Generates Cisco IOS ACLs.
  - `compiler_iptables.py`: Generates Linux `iptables` shell scripts.
  - `compiler_nftables.py`: Generates Linux `nftables` configurations.
- **Validator (`validator.py`)**: Checks the intermediate model for logical errors, including:
  - Conflicts (contradictory rules).
  - Duplicates and redundant permits.
  - Unreachable rules (shadowed by broader rules).
  - Missing infrastructure dependencies (DNS/DHCP).
- **Simulator (`simulator.py`)**: Simulates a packet flow through the rule set to predict the outcome (Allow/Deny) and explain which rule was triggered.

## 3. DSL Grammar & Syntax
The language allows the definition of Roles, Networks, VPN pools, Services, and Access Rules.

### Defining Entities
- **Roles**: `role <RoleName>`
  - Example: `role Students`
- **Networks**: `network <NetworkName> <CIDR>`
  - Example: `network Student_Net 10.10.10.0/24`
- **VPN Pools**: `vpn <VPNRoleName> <CIDR>`
  - Example: `vpn Remote_Staff 10.8.0.0/24`
- **Services**: `service <ServiceName> <Protocol> <Port>`
  - Example: `service HTTP tcp 80`

### Defining Rules
Rules define the traffic flow from a Source to a Destination using a specific Service.
Syntax: `<allow|deny> <SourceRole/Network> -> <DestinationNetwork> service <ServiceName>`
- Examples:
  - `allow Students -> Internet service HTTP`
  - `deny Guests -> Internal_Network service ANY`

## 4. Infrastructure Dependencies (DNS/DHCP)
The engine is DHCP/DNS-aware. If an administrator allows a role to access an external network (e.g., Internet) but forgets to explicitly allow DNS or DHCP, the `validator.py` will detect this and flag it as a `missing_dependency`. 

## 5. Getting Started

### Prerequisites
- Python 3.8+
- `lark` parser library
- `pytest` (for running unit tests)

### Installation
1. Create and activate a virtual environment (optional but recommended):
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
2. Install dependencies:
   ```bash
   pip install lark pytest
   ```

### Running the Demo
A predefined policy is located in `policy.txt`. To run the compiler and validation engine, execute:
```bash
python3 main.py
```
This will:
1. Parse the `policy.txt` file.
2. Output a summary to the console.
3. Generate multiple configuration files inside the `outputs/` directory:
   - `acl.txt` (Cisco ACL)
   - `firewall.sh` (iptables script)
   - `firewall.nft` (nftables config)
   - `model.json` (Intermediate JSON Model)
   - `validation_matrix.json` (A matrix testing all permutations of roles to destinations)
   - `report.json` (Conflicts, redundancies, and missing dependencies)

### Running Unit Tests
To run the automated tests against the parser, simulator, and validator, use:
```bash
pytest tests/
```

## 6. Project Scope Verification (Project 7 Requirements)
- **ACL logic, VLAN/Wireless roles**: Supported via the `network` and `role` primitives.
- **VPN access policy**: Supported natively via the `vpn` primitive which is tracked distinctly in the rule compilation.
- **Firewall generation**: Supports Cisco, Iptables, and Nftables outputs.
- **Simulator & Validation Matrix**: `validation_matrix()` outputs a complete state matrix verifying intended access.
