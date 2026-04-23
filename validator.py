def detect_conflicts(model):
    seen = {}
    conflicts = []

    for i, rule in enumerate(model["rules"], start=1):
        key = (rule["src"], rule["dst"], rule["service"])

        if key in seen:
            old_rule = seen[key]

            if old_rule["action"] != rule["action"]:
                conflicts.append({
                    "first_rule_number": old_rule["rule_number"],
                    "second_rule_number": i,
                    "src": rule["src"],
                    "dst": rule["dst"],
                    "service": rule["service"],
                    "first_action": old_rule["action"],
                    "second_action": rule["action"],
                })
        else:
            seen[key] = {
                "rule_number": i,
                "action": rule["action"]
            }

    return conflicts


def detect_duplicates(model):
    seen = {}
    duplicates = []

    for i, rule in enumerate(model["rules"], start=1):
        key = (rule["action"], rule["src"], rule["dst"], rule["service"])

        if key in seen:
            duplicates.append({
                "first_rule_number": seen[key],
                "duplicate_rule_number": i,
                "action": rule["action"],
                "src": rule["src"],
                "dst": rule["dst"],
                "service": rule["service"],
            })
        else:
            seen[key] = i

    return duplicates


def rule_matches(rule, src, dst, service):
    src_match = rule["src"] == src or rule["src"] == "any"
    dst_match = rule["dst"] == dst or rule["dst"] == "any"
    service_match = rule["service"] == service or rule["service"] == "ANY"
    return src_match and dst_match and service_match


def detect_unreachable_rules(model):
    unreachable = []

    for i, current_rule in enumerate(model["rules"]):
        for j in range(i):
            previous_rule = model["rules"][j]

            same_or_wider_src = (
                previous_rule["src"] == current_rule["src"]
                or previous_rule["src"] == "any"
            )
            same_or_wider_dst = (
                previous_rule["dst"] == current_rule["dst"]
                or previous_rule["dst"] == "any"
            )
            same_or_wider_service = (
                previous_rule["service"] == current_rule["service"]
                or previous_rule["service"] == "any"
            )

            different_action = previous_rule["action"] != current_rule["action"]

            if (
                same_or_wider_src
                and same_or_wider_dst
                and same_or_wider_service
                and different_action
            ):
                unreachable.append({
                    "blocked_rule_number": i + 1,
                    "blocking_rule_number": j + 1,
                    "action": current_rule["action"],
                    "src": current_rule["src"],
                    "dst": current_rule["dst"],
                    "service": current_rule["service"],
                })
                break

    return unreachable


def detect_redundant_rules(model):
    redundant = []

    for i, current_rule in enumerate(model["rules"]):
        for j in range(i):
            previous_rule = model["rules"][j]

            same_action = previous_rule["action"] == current_rule["action"]

            same_or_wider_src = (
                previous_rule["src"] == current_rule["src"]
                or previous_rule["src"] == "any"
            )
            same_or_wider_dst = (
                previous_rule["dst"] == current_rule["dst"]
                or previous_rule["dst"] == "any"
            )
            same_or_wider_service = (
                previous_rule["service"] == current_rule["service"]
                or previous_rule["service"] == "any"
            )

            if (
                same_action
                and same_or_wider_src
                and same_or_wider_dst
                and same_or_wider_service
            ):
                redundant.append({
                    "redundant_rule_number": i + 1,
                    "covered_by_rule_number": j + 1,
                    "action": current_rule["action"],
                    "src": current_rule["src"],
                    "dst": current_rule["dst"],
                    "service": current_rule["service"],
                })
                break

    return redundant


def validation_matrix(model):
    matrix = []

    roles = model["roles"]
    destinations = sorted(set(rule["dst"] for rule in model["rules"]))
    services = sorted(set(rule["service"] for rule in model["rules"]))

    for src in roles:
        for dst in destinations:
            for service in services:
                result = "deny"

                for rule in model["rules"]:
                    if rule_matches(rule, src, dst, service):
                        result = rule["action"]
                        break

                matrix.append((src, dst, service, result))

    return matrix