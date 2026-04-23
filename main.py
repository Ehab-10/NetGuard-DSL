from parser import parse_policy
from model import build_model
from compiler_iptables import generate_iptables
from compiler_acl import generate_cisco_acl
from simulator import simulate, explain
from validator import detect_conflicts, detect_duplicates , validation_matrix

# Read policy file
with open("policy.txt") as f:
    text = f.read()

# Parse
data = parse_policy(text)

# Build model
model = build_model(data)

print("=== MODEL ===")
print(model)

print("\n=== IPTABLES ===")
for r in generate_iptables(model):
    print(r)

print("\n=== CISCO ACL ===")
for r in generate_cisco_acl(model):
    print(r)

print("\n=== SIMULATION ===")
result = simulate(model, "Students", "Internet", "HTTP")
print(result.upper())

print("\n=== EXPLAIN ===")
print(explain(model, "Students", "Internet", "HTTP"))

print("\n=== CONFLICTS ===")
print(detect_conflicts(model))

print("\n=== DUPLICATES ===")
print(detect_duplicates(model))

print("\n=== VALIDATION MATRIX ===")
for row in validation_matrix(model):
    print(row)

print("\n=== INTERACTIVE SIMULATION ===")

while True:
    src = input("Enter source role (or 'exit'): ").strip()
    if src.lower() == "exit":
        break

    dst = input("Enter destination: ").strip()
    service = input("Enter service (HTTP/HTTPS/SSH/FTP/etc): ").strip()

    result = simulate(model, src, dst, service)

    print("\n=== RESULT ===")
    print(result.upper())

    print("\n=== EXPLAIN ===")
    print(explain(model, src, dst, service))
    print("\n-----------------------------")