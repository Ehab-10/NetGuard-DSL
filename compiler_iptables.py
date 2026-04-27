from utils import get_network, get_service


def generate_iptables(model):
    rules = []

    rules.append("#!/bin/bash")
    rules.append("# Generated Linux iptables firewall rules")
    rules.append("iptables -F")
    rules.append("iptables -P FORWARD DROP")

    for rule in model["rules"]:
        action = "ACCEPT" if rule["action"] == "allow" else "DROP"

        src_ip = get_network(model, rule["src"])
        dst_ip = get_network(model, rule["dst"])
        service = get_service(model, rule["service"])

        if not src_ip:
            rules.append(f"# ERROR: unknown source network: {rule['src']}")
            continue

        if not dst_ip:
            rules.append(f"# ERROR: unknown destination network: {rule['dst']}")
            continue

        if not service:
            rules.append(f"# ERROR: unknown service: {rule['service']}")
            continue

        protocol = service["protocol"]
        port = service["port"]

        if protocol == "ip" or port is None:
            cmd = f"iptables -A FORWARD -s {src_ip} -d {dst_ip} -j {action}"
        else:
            cmd = (
                f"iptables -A FORWARD -s {src_ip} -d {dst_ip} "
                f"-p {protocol} --dport {port} -j {action}"
            )

        if rule["src"] in model.get("vpn_pools", {}):
            cmd += "    # VPN traffic"

        rules.append(cmd)

    return rules