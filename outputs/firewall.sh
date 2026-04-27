#!/bin/bash
# Generated Linux iptables firewall rules
iptables -F
iptables -P FORWARD DROP
iptables -A FORWARD -s 10.10.10.0/24 -d 10.10.1.10/32 -p udp --dport 53 -j ACCEPT
iptables -A FORWARD -s 10.10.10.0/24 -d 10.10.1.20/32 -p udp --dport 67 -j ACCEPT
iptables -A FORWARD -s 10.10.20.0/24 -d 10.10.1.10/32 -p udp --dport 53 -j ACCEPT
iptables -A FORWARD -s 10.10.20.0/24 -d 10.10.1.20/32 -p udp --dport 67 -j ACCEPT
iptables -A FORWARD -s 10.10.40.0/24 -d 10.10.1.10/32 -p udp --dport 53 -j ACCEPT
iptables -A FORWARD -s 10.10.40.0/24 -d 10.10.1.20/32 -p udp --dport 67 -j ACCEPT
iptables -A FORWARD -s 10.8.0.0/24 -d 10.10.1.10/32 -p udp --dport 53 -j ACCEPT    # VPN traffic
iptables -A FORWARD -s 10.8.0.0/24 -d 10.10.1.20/32 -p udp --dport 67 -j ACCEPT    # VPN traffic
iptables -A FORWARD -s 10.10.10.0/24 -d 0.0.0.0/0 -p tcp --dport 80 -j ACCEPT
iptables -A FORWARD -s 10.10.10.0/24 -d 0.0.0.0/0 -p tcp --dport 443 -j ACCEPT
iptables -A FORWARD -s 10.10.20.0/24 -d 10.10.99.0/24 -p tcp --dport 22 -j ACCEPT
iptables -A FORWARD -s 10.10.30.0/24 -d 10.10.0.0/16 -j DROP
iptables -A FORWARD -s 10.10.30.0/24 -d 0.0.0.0/0 -p tcp --dport 80 -j ACCEPT
iptables -A FORWARD -s 10.10.40.0/24 -d 10.10.40.10/32 -p tcp --dport 443 -j ACCEPT
iptables -A FORWARD -s 10.8.0.0/24 -d 10.10.10.0/24 -j DROP    # VPN traffic
iptables -A FORWARD -s 10.8.0.0/24 -d 10.10.40.10/32 -p tcp --dport 443 -j ACCEPT    # VPN traffic
iptables -A FORWARD -s 10.10.10.0/24 -d 0.0.0.0/0 -p tcp --dport 80 -j ACCEPT
iptables -A FORWARD -s 10.10.20.0/24 -d 10.10.99.0/24 -p tcp --dport 22 -j DROP