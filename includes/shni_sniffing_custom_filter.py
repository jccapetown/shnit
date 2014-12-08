#Custom sniffing function for shni
from scapy.all import *

packetCount=0
def custom_filter(packet):
		global packetCount
		packetCount += 1
		#return "Packet #%s: %s ==> %s" % (packetCount, packet[0][1].src, packet[0][1].dst)
		return packet.summary()


def ftp_cred(packet):
	server = ''
	if IP in packet:
		server = packet[IP].dst

	if TCP in packet:
		if (packet[TCP].dport == 21) or  (packet[TCP].sport == 21):
			if Raw in packet:
				rawpkt = str(packet[Raw]).strip()
				if "USER " in rawpkt:
					print  server, ": ", rawpkt
					#return  server, ": ", rawpkt
				if "PASS " in rawpkt:
					print server, ": ", rawpkt
					#return server, ": ", rawpkt
