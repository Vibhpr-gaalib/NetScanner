#!/usr/bin/env python

import scapy.all as scapy
import optparse;

def scan(ipaddress):
    arp_request = scapy.ARP();
    arp_request.pdst = ipaddress;
    boradcast = scapy.Ether()
    boradcast.dst = "ff:ff:ff:ff:ff:ff";
    arp_request_broadcast = boradcast/arp_request;
    answered,unanswered = scapy.srp(arp_request_broadcast,timeout=1,verbose=False);
    print("[-]----------------------------------------------------------------------------")
    print("[+] Getting response from ")
    print("Mac Address\t\t\t Ip Address\n[-]----------------------------------------------------------------------------");
    for element in answered:
        print(element[1].hwsrc,"\t\t",element[1].psrc);
parser = optparse.OptionParser();
parser.add_option("-i","--ipaddress",dest="Single_ip",help = "For Single Ip eg:- -ip 10.10.10.1");
parser.add_option("-r","--iprange",dest="Ip_range",help="For a entire ip-range eg:- --ipr 10.10.10.1/24");
(options,arguments)= parser.parse_args();

if not options.Single_ip and not options.Ip_range:
    parser.error('Please add a single ip or an ip-range.');
elif options.Single_ip and  options.Ip_range :
    parser.error("Provide either a ip or an ip-range at a time");
elif options.Single_ip:
    scan(options.Single_ip);
else:
    scan(options.Ip_range);