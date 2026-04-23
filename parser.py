from lark import Lark, Transformer

grammar = r"""
start: statement+

?statement: role_def
          | vpn_def
          | rule

role_def: "role" NAME
vpn_def: "vpn" NAME CIDR
rule: ACTION NAME "->" NAME "service" SERVICE

ACTION: "allow" | "deny"
SERVICE: "HTTP" | "HTTPS" | "SSH" | "DNS" | "DHCP" | "FTP" | "ANY"
NAME: /[a-zA-Z_][a-zA-Z0-9_]*/
CIDR: /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+/

%import common.WS
%ignore WS
"""

parser = Lark(grammar)


class PolicyTransformer(Transformer):
    def start(self, items):
        return items

    def role_def(self, items):
        return ("role", str(items[0]))

    def vpn_def(self, items):
        return {
            "type": "vpn",
            "name": str(items[0]),
            "cidr": str(items[1]),
        }

    def rule(self, items):
        return {
            "type": "rule",
            "action": str(items[0]),
            "src": str(items[1]),
            "dst": str(items[2]),
            "service": str(items[3]),
        }


def clean_policy(text):
    lines = text.split("\n")
    cleaned = []

    for line in lines:
        line = line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        cleaned.append(line)

    return "\n".join(cleaned)


def parse_policy(text):
    text = clean_policy(text)
    tree = parser.parse(text)
    return PolicyTransformer().transform(tree)