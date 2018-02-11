#!/usr/local/bin/python
 
from pyrad.packet import Packet
from pyrad.dictionary import Dictionary

from scapy.all import sniff, Radius, Dot1Q, UDP, TCP, Raw, IP, Ether, Dot3
from scapy.all import *
import sys

import pcappy as pcap
conf.use_pcap=True

#print conf.L2listen

if(len(sys.argv)>1):
    infile=sys.argv[1]
else:
    infile="sniff.pcap"

if(len(sys.argv)>2):
    outfile=sys.argv[2]
else:
    outfile="nat.log"

#print infile

def parse_packet(packet):
    try: 
        if(packet.haslayer(Ether)):
            if(packet.haslayer(Dot1Q)):
                #packet.show()
                if(packet.haslayer(TCP)):
                    pass
                elif(packet.haslayer(UDP)):
                    data = packet[Raw].load
		    print data.split()[-1]
	        else:
                    #print "vlan no tcp"
                    pass
            else:
                #packet.show()
                if(packet.haslayer(TCP)):
                    pass
                elif(packet.haslayer(UDP)):
		    #packet[UDP].payload.show()
                    data = packet[Raw].load
		    print data.split()[-1]
	        else:
                    #packet.show()
                    pass
	else:
            #data = packet[Padding].load
	    #print data
	    pass
    except:
        print "error"

with open(outfile, 'w') as fout:
    sniff(offline=infile, prn=parse_packet, lfilter = lambda x: x.haslayer(Ether), timeout= 10, store=0)
