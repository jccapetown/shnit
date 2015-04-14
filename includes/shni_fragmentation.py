#fragemntation methods for the shni framework
from scapy.all import *
from netaddr import *
from formatting import bcolors


#Intercept signal
import shni_signals
import signal
import sys

class frag_class():
	fragments=0
	fragment_size=16
	originaldata = ''
	packet = None

	packet_layer_1 = None
	packet_layer_2 = None
	packet_layer_3 = None

	#def compile(self):
		

	def show_original_packet(self):
		os.system('clear')
		print "Shni - Fragmentation (original Packet)"
		print "======================================"
		print " "	
		packet = self.packet_layer_1/self.packet_layer_2/self.originaldata	
		packet.show2()
		raw_input("Continue")

	
	#def build_fragments



#Check for interrupts
interrupted = False

def view_fragmentation_menu(shni):
	if shni.config_exist('network'):
		ip = IPNetwork(shni.config['network'])

		clFragment = frag_class()
		while 1==1:
			os.system('clear')
			print "Shni - Fragmentation - Not Functional - Under Construction"
			print "================"
			print ""
			print "Current Fagmentation info"
			print "-------------------------"
			print	"Data Size           :	%s" %  len(clFragment.originaldata)
			print	"Fragement size      :	%s" %  clFragment.fragment_size
			print	"Fragements          :	%s" %  clFragment.fragments
			print	"Ip Header Created   :	%s" %  (clFragment.packet_layer_1 != None)
			print	"Proto layer Created :	%s" %  (clFragment.packet_layer_2 != None)
			
			print ""
			print ""
			print "Menu"
			print "===="
			print "1. Create Ip Header"
			print "2. Create protocol layer"
			print "3. Set original data"
			print "4. Set fragmentation size (bytes)"
			print "5. Show original packet"

			print " "
			print "x. Exit"
			print ""
			value = raw_input("Select an option from the menu: ")

			if value == 'x':
				break

			
			#if value == '1':
			#	create_ip_header(clFragment)

			#if value == '2':
			#	create_proto_layer(clFragment)
		
			#if value == '3':
			#	set_original_data(clFragment)
			
			#if value == '4':
			#	set_fragment_size(clFragment)

			#if value == '5':
			#	clFragment.show_original_packet()


def create_ip_header(clFragment):
		os.system('clear')
		print "Shni - Fragmentation (Ip Header)"
		print "==============================="
		print ""
		dstip = raw_input("Enter dst IP [default]: ")
		ipid = raw_input("Enter the IP ID: ")
		
		ipheader = IP()
		if dstip != '':
			ipheader.dst = dstip
		if ipid != '':
			ipheader.id = int(ipid)

		clFragment.packet_layer_1 = ipheader


def create_proto_layer(clFragment):
		os.system('clear')
		print "Shni - Fragmentation (protocol layer)"
		print "==============================="
		print ""		
		proto = raw_input("Enter protocol [icmp]: ")
	
		if proto.lower().strip() == '':
			proto = 'icmp'


		if proto.lower().strip() == 'icmp':
			pl2 = ICMP()
			icmptype = raw_input("Enter icmp type [8]: ")
			icmpcode = raw_input("Enter icmp code [0]: ")
			if icmptype.lower().strip() == '':
				icmptype=8
			if icmpcode.lower().strip() == '':
				icmpcode=0
			pl2.type=int(icmptype)
			pl2.code = int(icmpcode)
			clFragment.packet_layer_2 = pl2


def create_protocol_layer(clFragment):
		os.system('clear')
		print "Shni - Fragmentation (Ip Header)"
		print "==============================="
		print ""
		dstip = raw_input("Enter dst IP [default]: ")
		ipid = raw_input("Enter the IP ID: ")
		
		ipheader = IP()
		if dstip != '':
			ipheader.dst = dstip
		if ipid != '':
			ipheader.id = ipid

		clFragment.packet_layer_1 = ipheader


def set_original_data(clFragment):
		os.system('clear')
		print "Shni - Fragmentation (Set data)"
		print "==============================="
		print ""
		data = raw_input("Enter Original Packet data: ")
		clFragment.originaldata = data


def set_fragment_size(clFragment):
		os.system('clear')
		print "Shni - Fragmentation (Set size)"
		print "==============================="
		print ""
		size = raw_input("Enter fragment size (bytes): ")
		clFragment.fragment_size = int(size)
		




