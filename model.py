def build_model(data):
    model = {
        "roles": [],
        "rules": [],
        "vpn_pools": {}
    }

    for item in data:
        if isinstance(item, tuple) and item[0] == "role":
            model["roles"].append(item[1])

        elif isinstance(item, dict) and item.get("type") == "vpn":
            model["vpn_pools"][item["name"]] = item["cidr"]

            if item["name"] not in model["roles"]:
                model["roles"].append(item["name"])

        elif isinstance(item, dict) and item.get("type") == "rule":
            model["rules"].append(item)

    return model