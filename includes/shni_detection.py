#Virus hunting methods for the shni framework
from scapy.all import *
from netaddr import *
from formatting import bcolors


#Intercept signal
import shni_signals
import signal
import sys


#Check for interrupts
interrupted = False

def view_detection_menu(shni):
	if shni.config_exist('network'):
		ip = IPNetwork(shni.config['network'])

		while 1==1:
			os.system('clear')
			print "Shni - Detection"
			print "================"
			print ""
			print "Menu"
			print "===="
			print "1. Trace Route"

			print " "
			print "x. Exit"
			print ""
			value = raw_input("Select an option from the menu: ")

			if value == 'x':
				break

			if value == '1':
				tracert(shni)


def tracert(shni):
		os.system('clear')
		print "Shni - Trace Route"
		print "=================="
		print ""
		hostname = raw_input("Enter Hostname: ")

		print ""
		print "Trying UDP"
		print "=========="

		for i in range(1, 28):
				pkt = IP(dst=hostname, ttl=i) / UDP(dport=33434)
				# Send the packet and get a reply
				reply = sr1(pkt, verbose=0, timeout=1)
				destinationreached = False
				if reply is None:
						# No reply =(
						print "%d hops away: " % i , "No Reply. Possibly Blocked"
						print "Rage quit!"
						break
				elif reply.type == 3:
						# We've reached our destination
						print "Done!", reply.src
						break
				else:
						# We're in the middle somewhere
						print "%d hops away: " % i , reply.src
		

		print ""
		print "Trying TCP"
		print "=========="
		for i in range(1, 28):
				pkt = IP(dst=hostname, ttl=i,id=RandShort())/TCP(flags=0x2)
				# Send the packet and get a reply
				reply = sr1(pkt, verbose=0, timeout=1)
				destinationreached = False
				if reply is None:
						# No reply =(
						print "%d hops away: " % i , "No Reply. Possibly Blocked"
						print "Rage quit!"
						break
				elif reply.type == 3:
						# We've reached our destination
						print "Done!", reply.src
						break
				else:
						# We're in the middle somewhere
						print "%d hops away: " % i , reply.src
			
		print " "		
		raw_input("Continue")



