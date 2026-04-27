import json
import os

from parser import parse_policy
from model import build_model
from compiler_iptables import generate_iptables
from compiler_acl import generate_cisco_acl
from compiler_nftables import generate_nftables
from simulator import simulate, explain
from validator import (
    detect_conflicts,
    detect_duplicates,
    detect_unreachable_rules,
    detect_redundant_rules,
    detect_missing_dependencies,
    validation_matrix
)


OUTPUT_DIR = "outputs"


def save_file(filename, lines):
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    path = os.path.join(OUTPUT_DIR, filename)

    with open(path, "w") as file:
        if isinstance(lines, list):
            file.write("\n".join(lines))
        else:
            file.write(str(lines))


def main():
    with open("policy.txt", "r") as file:
        text = file.read()

    parsed_data = parse_policy(text)
    model = build_model(parsed_data)

    iptables_rules = generate_iptables(model)
    nftables_rules = generate_nftables(model)
    cisco_acl_rules = generate_cisco_acl(model)

    conflicts = detect_conflicts(model)
    duplicates = detect_duplicates(model)
    unreachable = detect_unreachable_rules(model)
    redundant = detect_redundant_rules(model)
    missing_dependencies = detect_missing_dependencies(model)
    matrix = validation_matrix(model)

    save_file("firewall.sh", iptables_rules)
    save_file("firewall.nft", nftables_rules)
    save_file("acl.txt", cisco_acl_rules)
    save_file("model.json", json.dumps(model, indent=4))
    save_file("validation_matrix.json", json.dumps(matrix, indent=4))

    report = {
        "conflicts": conflicts,
        "duplicates": duplicates,
        "unreachable_rules": unreachable,
        "redundant_rules": redundant,
        "missing_dependencies": missing_dependencies,
        "total_rules": len(model["rules"]),
        "total_roles": len(model["roles"]),
        "total_networks": len(model["networks"]),
        "total_services": len(model["services"])
    }

    save_file("report.json", json.dumps(report, indent=4))

    print("=== MODEL ===")
    print(json.dumps(model, indent=4))

    print("\n=== IPTABLES ===")
    print("\n".join(iptables_rules))

    print("\n=== NFTABLES ===")
    print("\n".join(nftables_rules))

    print("\n=== CISCO ACL ===")
    print("\n".join(cisco_acl_rules))

    print("\n=== VALIDATION REPORT ===")
    print(json.dumps(report, indent=4))

    print("\n=== SIMULATION TEST ===")
    src = "Students"
    dst = "Internet"
    service = "HTTP"

    print(explain(model, src, dst, service))


if __name__ == "__main__":
    main()