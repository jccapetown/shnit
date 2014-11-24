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

def view_virus_menu(shni):
	if shni.config_exist('network'):
		ip = IPNetwork(shni.config['network'])

		
		#save the current ports
		shni.tmp_save_ports()

		#Load Virus details
		global viruslist
		viruslist = load_viruslist()
		shni.ports = []
		for item in viruslist:
			shni.ports.append(int(item[1]))
			

		while 1==1:
			os.system('clear')
			print "Shni - Virus detection"
			print "======================"
			print ""

			print "Network	: %s" % shni.config['network']
			print "IP's		 : %s" % len(list(ip))
			print "Virusses : %s" % len(viruslist)
			print "Timeout	: %s" % (shni.timeout)
	
			print ""
			print "Menu"
			print "===="
			print "1. View Virus List"
			print "2. Locate virusses"

			print " "
			print "x. Exit"
			print ""
			value = raw_input("Select an option from the menu: ")

			if value == 'x':
				break

			if value == '1':
				view_virus_list()

			if value == '2':
				locate_virus_port(shni)


	shni.tmp_load_ports()



def view_virus_list():
	global viruslist
	os.system('clear')
	print "Shni - Virus list"
	print "================="
	for ix,tmp in enumerate(viruslist):
		proto = tmp[0]
		port = tmp[1]
		name = tmp[2]
		print "%s. \t %s" % (ix, name)
	raw_input("Press any key to continue")
				


def load_viruslist():
	f = open ("includes/shni_viruslist.txt")
	lines = f.readlines()
	f.close()
	viruslist = []
	for item in lines:
		tmplist= item.split('|')
		proto = tmplist[0].strip().upper()
		port = int(tmplist[1].strip())
		name = tmplist[2].strip()
		viruslist.append( (proto, port, name	) )
	return viruslist	

	


def locate_virus_port(shni):
	try:
		os.system('clear')
		global viruslist


		print "Shni - Finding listening viruses/Trojans/RATS"
		print "============================================="
		print ""
		print "Getting ready to find all hosts with virus ports"
		print "NOTE*** You are responsible for confirming that these are not false positives"
		print "Finding malicious critters on all hosts....."
		print ""	
		ip = IPNetwork(shni.config['network'])
		
		iplist = []
		if len(ip) == 1:
			iplist = ip
		else:
			iplist = list(ip)
		
		count = 0	
		
		signal.signal(signal.SIGINT,shni.interrupt_handler)

		progresscheck = []

		#First look by port. This way we can group virusses to ips
		global viruslist
		totalvirusses = len(viruslist) * len(iplist)
		for item in viruslist:
			proto = item[0]
			dst_port = item[1]
			name = item[2]	
			count += 1
		
			print "Searching - (%s port: %s)	%s" % (proto, dst_port, name )
		
			for networkitem in iplist:
				src_port = RandShort()
				dst_ip = str(networkitem)
				

				if proto.upper() == 'TCP':
					tcp_stealth_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=shni.timeout, verbose=False)
					if(tcp_stealth_scan_resp!=None):
						if(tcp_stealth_scan_resp.haslayer(TCP)):
							if(tcp_stealth_scan_resp.getlayer(TCP).flags == 0x12):
								send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="R"),timeout=shni.timeout, verbose=False)
								print bcolors.OKGREEN + " "*2,	"Possible virus detected on ",dst_ip + bcolors.ENDC

				
				if proto.upper() == 'UDP':
					udp_scan(dst_ip,dst_port,shni.timeout)
		


				progress =	round(float(count) / float(totalvirusses) * 100)
				if progress % 5 == 0:
					if progress not in progresscheck:			
						progresscheck.append(progress)
						print bcolors.OKBLUE + str(progress), "% Complete:", count, " of ",	totalvirusses, " inspections", 	bcolors.ENDC
	
		
			#check for user interrupt		
			if shni.interrupted:
				shni.interrupted = False
				return

		print ""
		raw_input("Press any key to continue")

	except Exception, e:
		raw_input("Press any key to continue")
				


def udp_scan(dst_ip,dst_port,dst_timeout):
	try:
		udp_scan_resp = sr1(IP(dst=dst_ip)/UDP(dport=dst_port),timeout=dst_timeout, verbose=False)
		if udp_scan_resp!=None:
			if (udp_scan_resp.haslayer(UDP)):
				print bcolors.OKGREEN + " "*2,	"Possible virus detected on ",dst_ip + bcolors.ENDC
	except Exception, e:
		print e
		raw_input("Error")
	
