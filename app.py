import os
from flask import Flask, render_template, request, send_from_directory, Response

from parser import parse_policy
from model import build_model
from compiler_iptables import generate_iptables
from compiler_acl import generate_cisco_acl
from simulator import simulate, explain
from validator import (
    detect_conflicts,
    detect_duplicates,
    detect_unreachable_rules,
    detect_redundant_rules,
    validation_matrix,
)
import json
app = Flask(__name__)

OUTPUT_DIR = "outputs"


def load_policy(policy_text):
    data = parse_policy(policy_text)
    model = build_model(data)
    return model


def save_outputs(
    model,
    iptables_rules,
    cisco_acl_rules,
    conflicts,
    duplicates,
    unreachable_rules,
    redundant_rules,
    matrix,
):
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    with open(os.path.join(OUTPUT_DIR, "acl.txt"), "w") as f:
        for rule in cisco_acl_rules:
            f.write(rule + "\n")

    with open(os.path.join(OUTPUT_DIR, "firewall.sh"), "w") as f:
        f.write("#!/bin/bash\n")
        for rule in iptables_rules:
            f.write(rule + "\n")

    with open(os.path.join(OUTPUT_DIR, "report.txt"), "w") as f:
        f.write("=== MODEL ===\n")
        f.write(str(model) + "\n\n")

        f.write("=== CONFLICTS ===\n")
        if conflicts:
            for c in conflicts:
                f.write(
                    f"Rule #{c['first_rule_number']} conflicts with Rule #{c['second_rule_number']} "
                    f"for {c['src']} -> {c['dst']} ({c['service']}): "
                    f"{c['first_action']} vs {c['second_action']}\n"
                )
        else:
            f.write("No conflicts found\n")

        f.write("\n=== DUPLICATES ===\n")
        if duplicates:
            for d in duplicates:
                f.write(
                    f"Rule #{d['duplicate_rule_number']} duplicates Rule #{d['first_rule_number']}: "
                    f"{d['action']} {d['src']} -> {d['dst']} ({d['service']})\n"
                )
        else:
            f.write("No duplicate rules found\n")

        f.write("\n=== UNREACHABLE RULES ===\n")
        if unreachable_rules:
            for u in unreachable_rules:
                f.write(
                    f"Rule #{u['blocked_rule_number']} is unreachable because of Rule "
                    f"#{u['blocking_rule_number']}: "
                    f"{u['action']} {u['src']} -> {u['dst']} ({u['service']})\n"
                )
        else:
            f.write("No unreachable rules found\n")

        f.write("\n=== REDUNDANT RULES ===\n")
        if redundant_rules:
            for r in redundant_rules:
                f.write(
                    f"Rule #{r['redundant_rule_number']} is redundant because it is already covered by "
                    f"Rule #{r['covered_by_rule_number']}: "
                    f"{r['action']} {r['src']} -> {r['dst']} ({r['service']})\n"
                )
        else:
            f.write("No redundant rules found\n")

        f.write("\n=== VALIDATION MATRIX ===\n")
        for row in matrix:
            f.write(f"{row[0]} -> {row[1]} ({row[2]}): {row[3].upper()}\n")


@app.route("/", methods=["GET", "POST"])
def index():
    with open("policy.txt", "r") as f:
        default_policy = f.read()

    policy_text = default_policy
    model = None
    iptables_rules = []
    cisco_acl_rules = []
    conflicts = []
    duplicates = []
    unreachable_rules = []
    redundant_rules = []
    matrix = []
    sim_result = None
    sim_explain = None

    if request.method == "POST":
        policy_text = request.form.get("policy_text", default_policy)

        try:
            model = load_policy(policy_text)
            iptables_rules = generate_iptables(model)
            cisco_acl_rules = generate_cisco_acl(model)

            conflicts = detect_conflicts(model)
            duplicates = detect_duplicates(model)
            unreachable_rules = detect_unreachable_rules(model)
            redundant_rules = detect_redundant_rules(model)
            matrix = validation_matrix(model)

            save_outputs(
                model,
                iptables_rules,
                cisco_acl_rules,
                conflicts,
                duplicates,
                unreachable_rules,
                redundant_rules,
                matrix,
            )

            src = request.form.get("src", "").strip()
            dst = request.form.get("dst", "").strip()
            service = request.form.get("service", "").strip()

            if src and dst and service:
                sim_result = simulate(model, src, dst, service).upper()
                sim_explain = explain(model, src, dst, service)

        except Exception as e:
            sim_result = "ERROR"
            sim_explain = str(e)

    return render_template(
        "index.html",
        policy_text=policy_text,
        model=model,
        iptables_rules=iptables_rules,
        cisco_acl_rules=cisco_acl_rules,
        conflicts=conflicts,
        duplicates=duplicates,
        unreachable_rules=unreachable_rules,
        redundant_rules=redundant_rules,
        matrix=matrix,
        sim_result=sim_result,
        sim_explain=sim_explain,
    )


@app.route("/download/<path:filename>")
def download_file(filename):
    return send_from_directory(OUTPUT_DIR, filename, as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True, port=5000)