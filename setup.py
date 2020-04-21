#!/usr/bin/env python3

import subprocess
# uncomment for local machine
#subprocess.call("sudo iptables -I INPUT -j NFQUEUE --queue-num 0", shell=True)
#subprocess.call("sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0", shell=True)

# comment for local machine
subprocess.call("sudo iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True)
subprocess.call("sudo echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)