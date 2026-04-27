def build_model(data):
    model = {
        "roles": [],
        "networks": {},
        "services": {
            "ANY": {
                "protocol": "ip",
                "port": None
            }
        },
        "vpn_pools": {},
        "rules": []
    }

    for item in data:
        item_type = item.get("type")

        if item_type == "role":
            role_name = item["name"]

            if role_name not in model["roles"]:
                model["roles"].append(role_name)

        elif item_type == "network":
            model["networks"][item["name"]] = item["cidr"]

        elif item_type == "service":
            model["services"][item["name"]] = {
                "protocol": item["protocol"],
                "port": item["port"]
            }

        elif item_type == "vpn":
            model["vpn_pools"][item["name"]] = item["cidr"]
            model["networks"][item["name"]] = item["cidr"]

            if item["name"] not in model["roles"]:
                model["roles"].append(item["name"])

        elif item_type == "rule":
            model["rules"].append(item)

    return model