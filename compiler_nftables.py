from utils import get_network, get_service


def generate_nftables(model):
    rules = []

    rules.append("#!/usr/sbin/nft -f")
    rules.append("flush ruleset")
    rules.append("")
    rules.append("table inet access_policy {")
    rules.append("    chain forward {")
    rules.append("        type filter hook forward priority 0; policy drop;")

    for rule in model["rules"]:
        action = "accept" if rule["action"] == "allow" else "drop"

        src_ip = get_network(model, rule["src"])
        dst_ip = get_network(model, rule["dst"])
        service = get_service(model, rule["service"])

        if not src_ip or not dst_ip or not service:
            rules.append(f"        # ERROR: cannot compile rule {rule}")
            continue

        protocol = service["protocol"]
        port = service["port"]

        if protocol == "ip" or port is None:
            line = f"        ip saddr {src_ip} ip daddr {dst_ip} {action}"
        else:
            line = (
                f"        ip saddr {src_ip} ip daddr {dst_ip} "
                f"{protocol} dport {port} {action}"
            )

        if rule["src"] in model.get("vpn_pools", {}):
            line += " comment \"VPN traffic\""

        rules.append(line)

    rules.append("    }")
    rules.append("}")

    return rules