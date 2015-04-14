#Port Scanning methods for the shni framework
from scapy.all import *
from netaddr import *
from formatting import bcolors


#Intercept signal
import shni_signals
import signal
import sys


#Check for interrupts
interrupted = False

def view_portscan_menu(shni):
	if shni.config_exist('network'):
		ip = IPNetwork(shni.config['network'])

		while 1==1:
			os.system('clear')
			print "Shni - Port Scan"
			print "================"
			print ""

			print "Network  : %s" % shni.config['network']
			print "IP's     : %s" % len(list(ip))
			print "Ports    : %s" % len(shni.ports)
			print "Timeout  : %s" % (shni.timeout)
	
			print ""
			print "Menu"
			print "===="
			print "1. TCP Connect scan"
			print "2. TCP Stealth/Syn scan"
			print "3. TCP Xmas scan"
			print "4. TCP Fin scan"
			print "5. TCP Ack scan"
			print "6. TCP Window Scan"
			print "7. UDP Scan"
			print "8. Locate open port on network"

			print " "
			print "x. Exit"
			print ""
			value = raw_input("Select an option from the menu: ")

			if value == 'x':
				break

			if value == '1':
				tcp_connect_scan(shni)

			if value == '2':
				tcp_stealth_scan(shni)

			if value == '3':
				tcp_xmas_scan(shni)

	
			if value == '4':
				tcp_fin_scan(shni)

			if value == '5':
				tcp_ack_scan(shni)

			if value == '6':
				tcp_window_scan(shni)

			if value == '7':
				udp_scan(shni)
			
			if value == '8':
				locate_port(shni)



def tcp_connect_scan(shni):
	os.system('clear')
	print "Shni - TCP Connect Scan"
	print "======================="
	print ""
	print "Getting ready to scan all ips and ports."
	print "Building packets....."
	print ""	
	ip = IPNetwork(shni.config['network'])
	
	iplist = []
	if len(ip) == 1:
		iplist = ip
	else:
		iplist = list(ip)
		
	for networkitem in iplist:
		src_port = RandShort()
		dst_ip = str(networkitem)
		
		print dst_ip
		for dst_port in shni.ports:
			tcp_stealth_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=shni.timeout, verbose=False)
			if(tcp_stealth_scan_resp==None):
				print " "*2, str(dst_port), "\t Closed"
			elif(tcp_stealth_scan_resp.haslayer(TCP)):
				if(tcp_stealth_scan_resp.getlayer(TCP).flags == 0x12):
					send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="AR"),timeout=shni.timeout, verbose=False)
					print " "*2, str(dst_port), "\t Open"
				elif(tcp_stealth_scan_resp.getlayer(TCP).flags == 0x14):
						print " "*2, str(dst_port), "\t Closed"
					
	print ""
	raw_input("Press any key to continue")

def tcp_stealth_scan(shni):
	os.system('clear')
	print "Shni - TCP Stealth Scan"
	print "======================="
	print ""
	print "Getting ready to stealth scan all ips and ports."
	print "Building packets....."
	print ""	
	ip = IPNetwork(shni.config['network'])
		
	iplist = []
	if len(ip) == 1:
		iplist = ip
	else:
		iplist = list(ip)
		
	for networkitem in iplist:
		src_port = RandShort()
		dst_ip = str(networkitem)
		
		print dst_ip
		for dst_port in shni.ports:
			tcp_stealth_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=shni.timeout, verbose=False)
			if(tcp_stealth_scan_resp==None):
				print " "*2, str(dst_port), "\t Closed"
			elif(tcp_stealth_scan_resp.haslayer(TCP)):
				if(tcp_stealth_scan_resp.getlayer(TCP).flags == 0x12):
					send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="R"),timeout=shni.timeout, verbose=False)
					print " "*2, str(dst_port), "\t Open"
				elif(tcp_stealth_scan_resp.getlayer(TCP).flags == 0x14):
					print " "*2, str(dst_port), "\t Closed"
		print ""
	raw_input("Press any key to continue")

def tcp_xmas_scan(shni):
	os.system('clear')
	print "Shni - TCP X-mas Scan"
	print "======================="
	print ""
	print "Getting ready to xmas scan all ips and ports."
	print "Building packets....."
	print ""	
	ip = IPNetwork(shni.config['network'])
	
	iplist = []
	if len(ip) == 1:
		iplist = ip
	else:
		iplist = list(ip)
		
	for networkitem in iplist:
		src_port = RandShort()
		dst_ip = str(networkitem)
		
		print dst_ip
		for dst_port in shni.ports:
			xmas_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="FPU"),timeout=shni.timeout, verbose=False)
			if (str(type(xmas_scan_resp))=="<type 'NoneType'>"):
				print " "*2, str(dst_port), "\t Open|Filtered"
			elif(xmas_scan_resp.haslayer(TCP)):
				if(xmas_scan_resp.getlayer(TCP).flags == 0x14):
					print " "*2, str(dst_port), "\t Closed"
			elif(xmas_scan_resp.haslayer(ICMP)):
				if(int(xmas_scan_resp.getlayer(ICMP).type)==3 and int(xmas_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
					print " "*2, str(dst_port), "\t Filtered"

		print ""
	raw_input("Press any key to continue")

def tcp_fin_scan(shni):
	os.system('clear')
	print "Shni - TCP FIN Scan"
	print "======================="
	print ""
	print "Getting ready to fin scan all ips and ports."
	print "Building packets....."
	print ""	
	ip = IPNetwork(shni.config['network'])
	
	iplist = []
	if len(ip) == 1:
		iplist = ip
	else:
		iplist = list(ip)
		
	for networkitem in iplist:
		src_port = RandShort()
		dst_ip = str(networkitem)
		
		print dst_ip
		for dst_port in shni.ports:
			fin_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="F"),timeout=shni.timeout,verbose=False)
			if (str(type(fin_scan_resp))=="<type 'NoneType'>"):
				print " "*2, str(dst_port), "\t Open|Filtered"
			elif(fin_scan_resp.haslayer(TCP)):
				if(fin_scan_resp.getlayer(TCP).flags == 0x14):
					print " "*2, str(dst_port), "\t Closed"
			elif(fin_scan_resp.haslayer(ICMP)):
				if(int(fin_scan_resp.getlayer(ICMP).type)==3 and int(fin_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
					print " "*2, str(dst_port), "\t Filtered"
		print ""
	raw_input("Press any key to continue")

def tcp_null_scan(shni):
		os.system('clear')
		print "Shni - TCP Null Scan"
		print "======================="
		print ""
		print "Getting ready to Null scan all ips and ports."
		print "Building packets....."
		print ""	
		ip = IPNetwork(shni.config['network'])
		
		iplist = []
		if len(ip) == 1:
			iplist = ip
		else:
			iplist = list(ip)
			
		for networkitem in iplist:
			src_port = RandShort()
			dst_ip = str(networkitem)
			
			print dst_ip
			for dst_port in shni.ports:

				fin_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags=""),timeout=shni.timeout,verbose=False)
				if (str(type(fin_scan_resp))=="<type 'NoneType'>"):
					print " "*2, str(dst_port), "\t Open|Filtered"
				elif(fin_scan_resp.haslayer(TCP)):
					if(fin_scan_resp.getlayer(TCP).flags == 0x14):
						print " "*2, str(dst_port), "\t Closed"
				elif(fin_scan_resp.haslayer(ICMP)):
					if(int(fin_scan_resp.getlayer(ICMP).type)==3 and int(fin_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
						print " "*2, str(dst_port), "\t Filtered"

		print ""
		raw_input("Press any key to continue")


def tcp_ack_scan(shni):
		os.system('clear')
		print "Shni - TCP Ack Scan"
		print "======================="
		print ""
		print "Getting ready to Ack scan all ips and ports."
		print "Building packets....."
		print ""	
		ip = IPNetwork(shni.config['network'])
		
		iplist = []
		if len(ip) == 1:
			iplist = ip
		else:
			iplist = list(ip)
			
		for networkitem in iplist:
			src_port = RandShort()
			dst_ip = str(networkitem)
			
			print dst_ip
			for dst_port in shni.ports:

				ack_flag_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="A"),timeout=shni.timeout, verbose=False)
				if (str(type(ack_flag_scan_resp))=="<type 'NoneType'>"):
					print " "*2, str(dst_port), "\t Stateful firewall presentn(Filtered)"
				elif(ack_flag_scan_resp.haslayer(TCP)):
					if(ack_flag_scan_resp.getlayer(TCP).flags == 0x4):
						print " "*2, str(dst_port), "\t No firewalln(Unfiltered)"
				elif(ack_flag_scan_resp.haslayer(ICMP)):
					if(int(ack_flag_scan_resp.getlayer(ICMP).type)==3 and int(ack_flag_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
						print " "*2, str(dst_port), "\t Stateful firewall presentn(Filtered)"

		print ""
		raw_input("Press any key to continue")


def tcp_window_scan(shni):
		os.system('clear')
		print "Shni - TCP Window Scan"
		print "======================="
		print ""
		print "Getting ready to window scan all ips and ports."
		print "Building packets....."
		print ""	
		ip = IPNetwork(shni.config['network'])
		
		iplist = []
		if len(ip) == 1:
			iplist = ip
		else:
			iplist = list(ip)
			
		for networkitem in iplist:
			src_port = RandShort()
			dst_ip = str(networkitem)
			
			print dst_ip
			for dst_port in shni.ports:
				window_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="A"),timeout=shni.timeout, verbose=False)
				if (str(type(window_scan_resp))=="<type 'NoneType'>"):
					print " "*2, str(dst_port), "\t No Response"
				elif(window_scan_resp.haslayer(TCP)):
					if(window_scan_resp.getlayer(TCP).window == 0):
						print " "*2, str(dst_port), "\t Closed"
				elif(window_scan_resp.getlayer(TCP).window > 0):
					print " "*2, str(dst_port), "\t Open"

		print ""
		raw_input("Press any key to continue")



def udp_scan(shni):
		os.system('clear')
		print "Shni - UDP Scan"
		print "======================="
		print ""
		print "Getting ready to udp scan all ips and ports."
		print "Building packets....."
		print ""	
		ip = IPNetwork(shni.config['network'])
		
		iplist = []
		if len(ip) == 1:
			iplist = ip
		else:
			iplist = list(ip)
			
		for networkitem in iplist:
			src_port = RandShort()
			dst_ip = str(networkitem)
			
			print dst_ip
			for dst_port in shni.ports:

				def internal_udp_scan(dst_ip,dst_port,dst_timeout):
					udp_scan_resp = sr1(IP(dst=dst_ip)/UDP(dport=dst_port),timeout=dst_timeout, verbose=False)
					if udp_scan_resp==None:
						print " "*2, str(dst_port), "\t Open|Filtered"
					elif (udp_scan_resp.haslayer(UDP)):
						print " "*2, str(dst_port), "\t Open"
					elif(udp_scan_resp.haslayer(ICMP)):
						if(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code)==3):
							print " "*2, str(dst_port), "\t Closed"
					elif(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code) in [1,2,9,10,13]):
						print " "*2, str(dst_port), "\t Filtered"
 
				internal_udp_scan(dst_ip,dst_port,shni.timeout)


		print ""
		raw_input("Press any key to continue")



def locate_port(shni, useconfig = False):
		if not useconfig:
		 	locateport = raw_input("what port would you like to find [21]: ").strip()
		else:
			locateport = shni.config['ports']
		
		if locateport.strip() == '':
			locateport = '21'
 
		os.system('clear')
		
		print "Shni - Open Port Location"
		print "========================="
		print ""
		print "Getting ready to find all hosts in %s where port %s is open." %(shni.config['network'],  locateport)
		print "Finding hosts....."
		print ""	
		ip = IPNetwork(shni.config['network'])
		
		iplist = []
		if len(ip) == 1:
			iplist = ip
		else:
			iplist = list(ip)
		
		totalips = len(iplist)
		count = 0	
		
		signal.signal(signal.SIGINT,shni.interrupt_handler)

		progresscheck = []

		for networkitem in iplist:
			count += 1
			src_port = RandShort()
			dst_port = int(locateport)
			dst_ip = str(networkitem)
			
			tcp_stealth_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=shni.timeout, verbose=False)
			if(tcp_stealth_scan_resp!=None):
				if(tcp_stealth_scan_resp.haslayer(TCP)):
					if(tcp_stealth_scan_resp.getlayer(TCP).flags == 0x12):
						send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="R"),timeout=shni.timeout, verbose=False)
						print bcolors.OKGREEN +  "Port "*2, str(dst_port), "\t Open on ",dst_ip + bcolors.ENDC

			progress =  round(float(count) / float(totalips) * 100)
			if progress % 5 == 0:
				if progress not in progresscheck:			
					progresscheck.append(progress)
					print bcolors.OKBLUE + str(progress), "% Complete:", count, " of ",  totalips,  bcolors.ENDC
	
		
			#check for user interrupt		
			if shni.interrupted:
				shni.interrupted = False
				break

		print ""
		raw_input("Press any key to continue")

	


		
