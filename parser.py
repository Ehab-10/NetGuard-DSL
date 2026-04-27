from lark import Lark, Transformer

grammar = r"""
start: statement+

?statement: role_def
          | network_def
          | service_def
          | vpn_def
          | rule

role_def: "role" NAME
network_def: "network" NAME CIDR
service_def: "service" NAME PROTOCOL PORT
vpn_def: "vpn" NAME CIDR

rule: ACTION NAME "->" NAME "service" NAME

ACTION: "allow" | "deny"
PROTOCOL: "tcp" | "udp" | "ip"
NAME: /[a-zA-Z_][a-zA-Z0-9_]*/
CIDR: /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+/
PORT: /[0-9]+/

%import common.WS
%ignore WS
"""

parser = Lark(grammar, parser="lalr")


class PolicyTransformer(Transformer):
    def start(self, items):
        return items

    def role_def(self, items):
        return {
            "type": "role",
            "name": str(items[0])
        }

    def network_def(self, items):
        return {
            "type": "network",
            "name": str(items[0]),
            "cidr": str(items[1])
        }

    def service_def(self, items):
        return {
            "type": "service",
            "name": str(items[0]).upper(),
            "protocol": str(items[1]),
            "port": int(items[2])
        }

    def vpn_def(self, items):
        return {
            "type": "vpn",
            "name": str(items[0]),
            "cidr": str(items[1])
        }

    def rule(self, items):
        return {
            "type": "rule",
            "action": str(items[0]),
            "src": str(items[1]),
            "dst": str(items[2]),
            "service": str(items[3]).upper()
        }


def clean_policy(text):
    cleaned = []

    for line in text.splitlines():
        line = line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        if "#" in line:
            line = line.split("#", 1)[0].strip()

        cleaned.append(line)

    return "\n".join(cleaned)


def parse_policy(text):
    text = clean_policy(text)
    tree = parser.parse(text)
    return PolicyTransformer().transform(tree)