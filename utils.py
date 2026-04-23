SERVICE_PORTS = {
    "HTTP": 80,
    "HTTPS": 443,
    "SSH": 22,
    "DNS": 53,
    "DHCP": 67,
    "FTP": 21,
    "ANY": None,
}

ROLE_IPS = {
    "Students": "10.10.10.0/24",
    "Teachers": "10.10.20.0/24",
    "Guests": "10.10.30.0/24",
    "HR": "10.10.40.0/24",
    "Remote_Staff": "10.8.0.0/24",
}

DEST_IPS = {
    "Internet": "0.0.0.0/0",
    "Admin_Network": "10.10.99.0/24",
    "Internal_Network": "10.10.0.0/16",
    "DNS_Server": "10.10.1.10/32",
    "DHCP_Server": "10.10.1.20/32",
    "HR_Server": "10.10.40.10/32",
    "Student_Net": "10.10.10.0/24",
}

DEFAULT_DEPENDENCY_RULES = [
    {"dst": "DNS_Server", "service": "DNS"},
    {"dst": "DHCP_Server", "service": "DHCP"},
]