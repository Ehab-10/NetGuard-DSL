import ipaddress


def get_network(model, name):
    return model.get("networks", {}).get(name)


def get_service(model, name):
    name = name.upper()

    if name == "ANY":
        return {
            "protocol": "ip",
            "port": None
        }

    return model.get("services", {}).get(name)


def cidr_to_cisco(cidr):
    if cidr == "0.0.0.0/0":
        return "any"

    network = ipaddress.ip_network(cidr, strict=False)
    wildcard = ipaddress.IPv4Address(int(network.hostmask))

    return f"{network.network_address} {wildcard}"


def is_any(value):
    return str(value).upper() == "ANY" or str(value).lower() == "any"


DEPENDENCY_SERVICES = {
    "DNS": {
        "dst": "DNS_Server",
        "service": "DNS"
    },
    "DHCP": {
        "dst": "DHCP_Server",
        "service": "DHCP"
    }
}