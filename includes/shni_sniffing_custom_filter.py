#Custom sniffing function for shni
from scapy.all import *

packetCount=0
def custom_filter(packet):
		global packetCount
		packetCount += 1
		#return "Packet #%s: %s ==> %s" % (packetCount, packet[0][1].src, packet[0][1].dst)
		return packet.summary()
