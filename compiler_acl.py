from utils import SERVICE_PORTS, ROLE_IPS, DEST_IPS

def generate_cisco_acl(model):
    rules = []

    vpn_pools = model.get("vpn_pools", {})
    merged_role_ips = {**ROLE_IPS, **vpn_pools}

    for r in model["rules"]:
        action = "permit" if r["action"] == "allow" else "deny"
        src_ip = merged_role_ips.get(r["src"], "any")
        dst_ip = DEST_IPS.get(r["dst"], "any")
        service = r["service"]
        port = SERVICE_PORTS.get(service)

        if service == "ANY" or port is None:
            rule = f"{action} ip {src_ip} {dst_ip}"
        else:
            proto = "udp" if service in ("DNS", "DHCP") else "tcp"
            rule = f"{action} {proto} {src_ip} {dst_ip} eq {port}"

        if r["src"] in vpn_pools:
            rule += "  ! VPN traffic"

        rules.append(rule)

    return rules