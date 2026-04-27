def rule_matches(rule, src, dst, service):
    service = service.upper()

    src_match = rule["src"] == src or rule["src"].lower() == "any"
    dst_match = rule["dst"] == dst or rule["dst"].lower() == "any"
    service_match = rule["service"] == service or rule["service"] == "ANY"

    return src_match and dst_match and service_match


def simulate(model, src, dst, service):
    service = service.upper()

    for rule in model["rules"]:
        if rule_matches(rule, src, dst, service):
            return rule["action"]

    return "deny"


def explain(model, src, dst, service):
    service = service.upper()

    for index, rule in enumerate(model["rules"], start=1):
        if rule_matches(rule, src, dst, service):
            extra = ""

            if rule["src"] in model.get("vpn_pools", {}):
                vpn_ip = model["vpn_pools"][rule["src"]]
                extra = f"\nContext: {rule['src']} is a VPN role using pool {vpn_ip}"

            return (
                f"Result: {rule['action'].upper()}\n"
                f"Reason: matched rule #{index}\n"
                f"Rule: {rule['action']} {rule['src']} -> {rule['dst']} service {rule['service']}"
                f"{extra}"
            )

    return (
        "Result: DENY\n"
        f"Reason: no matching rule for {src} -> {dst} service {service}"
    )