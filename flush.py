#!/usr/bin/env python3

import subprocess
subprocess.call("sudo iptables --flush", shell=True)
subprocess.call("sudo echo 0 > /proc/sys/net/ipv4/ip_forward", shell=True)
