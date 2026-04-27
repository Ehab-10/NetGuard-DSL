from utils import get_network, get_service, cidr_to_cisco


def generate_cisco_acl(model):
    rules = []
    rules.append("! Generated Cisco ACL rules")

    acl_number = 100

    for rule in model["rules"]:
        action = "permit" if rule["action"] == "allow" else "deny"

        src_cidr = get_network(model, rule["src"])
        dst_cidr = get_network(model, rule["dst"])
        service = get_service(model, rule["service"])

        if not src_cidr:
            rules.append(f"! ERROR: unknown source network: {rule['src']}")
            continue

        if not dst_cidr:
            rules.append(f"! ERROR: unknown destination network: {rule['dst']}")
            continue

        if not service:
            rules.append(f"! ERROR: unknown service: {rule['service']}")
            continue

        src = cidr_to_cisco(src_cidr)
        dst = cidr_to_cisco(dst_cidr)

        protocol = service["protocol"]
        port = service["port"]

        if protocol == "ip" or port is None:
            line = f"access-list {acl_number} {action} ip {src} {dst}"
        else:
            line = f"access-list {acl_number} {action} {protocol} {src} {dst} eq {port}"

        if rule["src"] in model.get("vpn_pools", {}):
            line += "  ! VPN traffic"

        rules.append(line)

    return rules