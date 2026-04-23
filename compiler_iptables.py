from utils import SERVICE_PORTS, ROLE_IPS, DEST_IPS

def generate_iptables(model):
    rules = []

    vpn_pools = model.get("vpn_pools", {})
    merged_role_ips = {**ROLE_IPS, **vpn_pools}

    for r in model["rules"]:
        action = "ACCEPT" if r["action"] == "allow" else "DROP"
        src_ip = merged_role_ips.get(r["src"], "any")
        dst_ip = DEST_IPS.get(r["dst"], "any")
        service = r["service"]
        port = SERVICE_PORTS.get(service)

        if src_ip == "any" or dst_ip == "any":
            rules.append(f"# Unknown mapping for rule: {r}")
            continue

        if service == "ANY" or port is None:
            rule = f"iptables -A FORWARD -s {src_ip} -d {dst_ip} -j {action}"
        else:
            proto = "udp" if service in ("DNS", "DHCP") else "tcp"
            rule = (
                f"iptables -A FORWARD -s {src_ip} -d {dst_ip} "
                f"-p {proto} --dport {port} -j {action}"
            )

        if r["src"] in vpn_pools:
            rule += "    # VPN traffic"

        rules.append(rule)

    return rules