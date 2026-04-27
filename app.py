import json
import os

from flask import Flask, render_template, request, send_from_directory

from parser import parse_policy
from model import build_model
from compiler_iptables import generate_iptables
from compiler_acl import generate_cisco_acl
from compiler_nftables import generate_nftables
from simulator import simulate, explain
from validator import (
    detect_conflicts,
    detect_duplicates,
    detect_unreachable_rules,
    detect_redundant_rules,
    detect_missing_dependencies,
    validation_matrix,
)

app = Flask(__name__)

OUTPUT_DIR = "outputs"


def load_policy(policy_text):
    parsed_data = parse_policy(policy_text)
    model = build_model(parsed_data)
    return model


def save_text_file(filename, content):
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    path = os.path.join(OUTPUT_DIR, filename)

    with open(path, "w") as file:
        file.write(content)


def save_outputs(
    model,
    iptables_rules,
    nftables_rules,
    cisco_acl_rules,
    conflicts,
    duplicates,
    unreachable_rules,
    redundant_rules,
    missing_dependencies,
    matrix,
):
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    report = {
        "conflicts": conflicts,
        "duplicates": duplicates,
        "unreachable_rules": unreachable_rules,
        "redundant_rules": redundant_rules,
        "missing_dependencies": missing_dependencies,
        "total_rules": len(model["rules"]),
        "total_roles": len(model["roles"]),
        "total_networks": len(model["networks"]),
        "total_services": len(model["services"]),
    }

    save_text_file("firewall.sh", "\n".join(iptables_rules))
    save_text_file("firewall.nft", "\n".join(nftables_rules))
    save_text_file("acl.txt", "\n".join(cisco_acl_rules))
    save_text_file("model.json", json.dumps(model, indent=4))
    save_text_file("report.json", json.dumps(report, indent=4))
    save_text_file("validation_matrix.json", json.dumps(matrix, indent=4))

    readable_report = []
    readable_report.append("=== ACCESS POLICY DSL REPORT ===")
    readable_report.append("")

    readable_report.append("=== SUMMARY ===")
    readable_report.append(f"Total Rules: {len(model['rules'])}")
    readable_report.append(f"Total Roles: {len(model['roles'])}")
    readable_report.append(f"Total Networks: {len(model['networks'])}")
    readable_report.append(f"Total Services: {len(model['services'])}")
    readable_report.append(f"Conflicts: {len(conflicts)}")
    readable_report.append(f"Duplicates: {len(duplicates)}")
    readable_report.append(f"Unreachable Rules: {len(unreachable_rules)}")
    readable_report.append(f"Redundant Rules: {len(redundant_rules)}")
    readable_report.append(f"Missing Dependencies: {len(missing_dependencies)}")
    readable_report.append("")

    readable_report.append("=== CONFLICTS ===")
    if conflicts:
        for item in conflicts:
            readable_report.append(
                f"Rule #{item['first_rule_number']} conflicts with Rule #{item['second_rule_number']} "
                f"for {item['src']} -> {item['dst']} service {item['service']}: "
                f"{item['first_action']} vs {item['second_action']}"
            )
    else:
        readable_report.append("No conflicts found.")
    readable_report.append("")

    readable_report.append("=== DUPLICATES ===")
    if duplicates:
        for item in duplicates:
            readable_report.append(
                f"Rule #{item['duplicate_rule_number']} duplicates Rule #{item['first_rule_number']}: "
                f"{item['action']} {item['src']} -> {item['dst']} service {item['service']}"
            )
    else:
        readable_report.append("No duplicate rules found.")
    readable_report.append("")

    readable_report.append("=== UNREACHABLE RULES ===")
    if unreachable_rules:
        for item in unreachable_rules:
            readable_report.append(
                f"Rule #{item['blocked_rule_number']} is unreachable because of Rule "
                f"#{item['blocking_rule_number']}: "
                f"{item['action']} {item['src']} -> {item['dst']} service {item['service']}"
            )
    else:
        readable_report.append("No unreachable rules found.")
    readable_report.append("")

    readable_report.append("=== REDUNDANT RULES ===")
    if redundant_rules:
        for item in redundant_rules:
            readable_report.append(
                f"Rule #{item['redundant_rule_number']} is redundant because it is covered by Rule "
                f"#{item['covered_by_rule_number']}: "
                f"{item['action']} {item['src']} -> {item['dst']} service {item['service']}"
            )
    else:
        readable_report.append("No redundant rules found.")
    readable_report.append("")

    readable_report.append("=== MISSING DNS/DHCP DEPENDENCIES ===")
    if missing_dependencies:
        for item in missing_dependencies:
            readable_report.append(
                f"{item['role']} is missing {item['missing_service']}. "
                f"Required rule: {item['required_rule']}"
            )
    else:
        readable_report.append("No missing dependencies found.")
    readable_report.append("")

    readable_report.append("=== VALIDATION MATRIX ===")
    for row in matrix:
        readable_report.append(
            f"{row['src']} -> {row['dst']} service {row['service']}: {row['result'].upper()}"
        )

    save_text_file("report.txt", "\n".join(readable_report))


@app.route("/", methods=["GET", "POST"])
def index():
    with open("policy.txt", "r") as file:
        default_policy = file.read()

    policy_text = default_policy
    src = ""
    dst = ""
    service = ""

    model = None
    iptables_rules = []
    nftables_rules = []
    cisco_acl_rules = []

    conflicts = []
    duplicates = []
    unreachable_rules = []
    redundant_rules = []
    missing_dependencies = []
    matrix = []

    sim_result = None
    sim_explain = None
    error_message = None

    if request.method == "POST":
        policy_text = request.form.get("policy_text", default_policy)
        src = request.form.get("src", "").strip()
        dst = request.form.get("dst", "").strip()
        service = request.form.get("service", "").strip()

    try:
        model = load_policy(policy_text)

        iptables_rules = generate_iptables(model)
        nftables_rules = generate_nftables(model)
        cisco_acl_rules = generate_cisco_acl(model)

        conflicts = detect_conflicts(model)
        duplicates = detect_duplicates(model)
        unreachable_rules = detect_unreachable_rules(model)
        redundant_rules = detect_redundant_rules(model)
        missing_dependencies = detect_missing_dependencies(model)
        matrix = validation_matrix(model)

        save_outputs(
            model=model,
            iptables_rules=iptables_rules,
            nftables_rules=nftables_rules,
            cisco_acl_rules=cisco_acl_rules,
            conflicts=conflicts,
            duplicates=duplicates,
            unreachable_rules=unreachable_rules,
            redundant_rules=redundant_rules,
            missing_dependencies=missing_dependencies,
            matrix=matrix,
        )

        if src and dst and service:
            sim_result = simulate(model, src, dst, service).upper()
            sim_explain = explain(model, src, dst, service)

    except Exception as error:
        error_message = str(error)
        sim_result = "ERROR"
        sim_explain = str(error)

    return render_template(
        "index.html",
        policy_text=policy_text,
        src=src,
        dst=dst,
        service=service,
        model=model,
        iptables_rules=iptables_rules,
        nftables_rules=nftables_rules,
        cisco_acl_rules=cisco_acl_rules,
        conflicts=conflicts,
        duplicates=duplicates,
        unreachable_rules=unreachable_rules,
        redundant_rules=redundant_rules,
        missing_dependencies=missing_dependencies,
        matrix=matrix,
        sim_result=sim_result,
        sim_explain=sim_explain,
        error_message=error_message,
        model_json=json.dumps(model, indent=4) if model else "",
    )


@app.route("/download/<path:filename>")
def download_file(filename):
    return send_from_directory(OUTPUT_DIR, filename, as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True, port=5000)