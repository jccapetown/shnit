#graphing methods for shni
from scapy.all import *

def view_graphs_menu(shni):
	input = ""
	while input != 'x':

		os.system('clear')
		print "Shni - Graphing"
		print "==============="
		print "1. Host Conversation"
		print ""
		print "x. Exit"
		input = raw_input("Select an option: ")
	
		#CONFIG 
		if str(input) == '1':
			sniff_conversation(shni)



def get_packet(packet):
	return packet.summary()


def sniff_conversation(shni):
	os.system('clear')
	print "Remember to stop sniffing by pressing Ctl+C"
	print "You need Graphviz and Imagemagic to create conversations. Install with Apt-get or alike."
	sniff_filter = raw_input("Please enter the host ip to track [all]: ")
	if not sniff_filter == '':
		sniff_filter = "host %s" % sniff_filter
		
	packets = sniff(filter=sniff_filter, prn=get_packet)
	
	print "Creating Conversations...."
	packets.conversations()
	raw_input("continue...")	
