from simulator import simulate
from utils import DEPENDENCY_SERVICES


def is_wider_or_same(previous_value, current_value):
    return (
        previous_value == current_value
        or previous_value.upper() == "ANY"
        or previous_value.lower() == "any"
    )


def rule_covers(previous_rule, current_rule):
    src_ok = is_wider_or_same(previous_rule["src"], current_rule["src"])
    dst_ok = is_wider_or_same(previous_rule["dst"], current_rule["dst"])
    service_ok = is_wider_or_same(previous_rule["service"], current_rule["service"])

    return src_ok and dst_ok and service_ok


def detect_conflicts(model):
    conflicts = []

    for i, first in enumerate(model["rules"], start=1):
        for j, second in enumerate(model["rules"], start=1):
            if j <= i:
                continue

            same_src = first["src"] == second["src"]
            same_dst = first["dst"] == second["dst"]
            same_service = first["service"] == second["service"]
            different_action = first["action"] != second["action"]

            if same_src and same_dst and same_service and different_action:
                conflicts.append({
                    "first_rule_number": i,
                    "second_rule_number": j,
                    "src": first["src"],
                    "dst": first["dst"],
                    "service": first["service"],
                    "first_action": first["action"],
                    "second_action": second["action"]
                })

    return conflicts


def detect_duplicates(model):
    duplicates = []
    seen = {}

    for i, rule in enumerate(model["rules"], start=1):
        key = (
            rule["action"],
            rule["src"],
            rule["dst"],
            rule["service"]
        )

        if key in seen:
            duplicates.append({
                "first_rule_number": seen[key],
                "duplicate_rule_number": i,
                "action": rule["action"],
                "src": rule["src"],
                "dst": rule["dst"],
                "service": rule["service"]
            })
        else:
            seen[key] = i

    return duplicates


def detect_unreachable_rules(model):
    unreachable = []

    for i, current_rule in enumerate(model["rules"]):
        for j in range(i):
            previous_rule = model["rules"][j]

            if rule_covers(previous_rule, current_rule):
                if previous_rule["action"] != current_rule["action"]:
                    unreachable.append({
                        "blocked_rule_number": i + 1,
                        "blocking_rule_number": j + 1,
                        "action": current_rule["action"],
                        "src": current_rule["src"],
                        "dst": current_rule["dst"],
                        "service": current_rule["service"]
                    })
                    break

    return unreachable


def detect_redundant_rules(model):
    redundant = []

    for i, current_rule in enumerate(model["rules"]):
        for j in range(i):
            previous_rule = model["rules"][j]

            if rule_covers(previous_rule, current_rule):
                if previous_rule["action"] == current_rule["action"]:
                    redundant.append({
                        "redundant_rule_number": i + 1,
                        "covered_by_rule_number": j + 1,
                        "action": current_rule["action"],
                        "src": current_rule["src"],
                        "dst": current_rule["dst"],
                        "service": current_rule["service"]
                    })
                    break

    return redundant


def detect_missing_dependencies(model):
    """
    DNS/DHCP-aware validation.

    If a role has any allow rule to a non-infrastructure destination,
    it should also have DNS and DHCP access.
    """
    missing = []

    roles_with_access = set()

    for rule in model["rules"]:
        if rule["action"] == "allow":
            if rule["dst"] not in ["DNS_Server", "DHCP_Server"]:
                roles_with_access.add(rule["src"])

    for role in sorted(roles_with_access):
        for dependency_name, dependency in DEPENDENCY_SERVICES.items():
            dst = dependency["dst"]
            service = dependency["service"]

            result = simulate(model, role, dst, service)

            if result != "allow":
                missing.append({
                    "role": role,
                    "missing_service": dependency_name,
                    "required_rule": f"allow {role} -> {dst} service {service}"
                })

    return missing


def validation_matrix(model):
    matrix = []

    sources = sorted(set(model["roles"]))
    destinations = sorted(set(model["networks"].keys()))
    services = sorted(set(model["services"].keys()))

    for src in sources:
        for dst in destinations:
            if src == dst:
                continue

            for service in services:
                result = simulate(model, src, dst, service)

                matrix.append({
                    "src": src,
                    "dst": dst,
                    "service": service,
                    "result": result
                })

    return matrix