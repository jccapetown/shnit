#sniffing methods for shni
from scapy.all import *
import shni_sniffing_custom_filter

def view_sniffing_menu(shni):
	input = ""
	while input != 'x':

		os.system('clear')
		print "Sniffing"
		print "========"
		print "1. Sniff Packets (all)"
		print "2. Sniff ftp Details"
		print ""
		print "x. Exit"
		input = raw_input("Select an option: ")
	
		#CONFIG 
		if str(input) == '1':
			sniff_packets(shni)

		if str(input) == '2':
			sniff_ftp_creds(shni)

	
def sniff_packets(shni):
	os.system('clear')
	sniff_filter = raw_input("Please enter your filter [None]: ")
	#setup sniff, filtering for IP traffic
	packets = sniff(filter=sniff_filter,prn=shni_sniffing_custom_filter.custom_filter)	
	print"*******************"
	print "Creating Log file"
	f = open('logs/sniffer.log.txt',"rb+")
	print "Writing packets to log file"
	for pkt in packets:
		f.write("%s%s" % (pkt.summary, "\n"))
	f.close()
	print "Files have been written to 'logs/sniffer.log.txt'"
	raw_input("continue...")	



def sniff_ftp_creds(shni):
	os.system('clear')
	sniff(filter='port 21', prn=shni_sniffing_custom_filter.ftp_cred )	
	#packets = sniff(filter='port 21', prn=shni_sniffing_custom_filter.ftp_cred )	
	
	#print"*******************"
	#print "Creating Log file"
	#f = open('logs/sniffer.ftpcreds.log.txt',"rb+")
	#print "Writing packets to log file"
	#for pkt in packets:
	#	f.write("%s%s" % (pkt, "\n"))
	#f.close()
	#print "Files have been written to 'logs/sniffer.ftpcreds.log.txt'"
	raw_input("continue...")	


