def simulate(model, src, dst, service):
    service = service.upper()

    for r in model["rules"]:
        if (
            r["src"] == src and
            r["dst"] == dst and
            (r["service"] == service or r["service"] == "ANY")
        ):
            return r["action"]

    return "deny"


def explain(model, src, dst, service):
    service = service.upper()
    vpn_pools = model.get("vpn_pools", {})

    for i, r in enumerate(model["rules"], start=1):
        if (
            r["src"] == src and
            r["dst"] == dst and
            (r["service"] == service or r["service"] == "ANY")
        ):
            extra = ""
            if r["src"] in vpn_pools:
                extra = f"\nContext: Source role '{r['src']}' is a VPN role from pool {vpn_pools[r['src']]}"

            return (
                f"Result: {r['action'].upper()}\n"
                f"Reason: Matched rule #{i} -> "
                f"{r['action'].upper()} {r['src']} -> {r['dst']} (service {r['service']})"
                f"{extra}"
            )

    return (
        f"Result: DENY\n"
        f"Reason: No matching rule found for ({src} -> {dst} : {service})"
    )