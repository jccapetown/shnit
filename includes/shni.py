from netaddr import *
import os
import ports
import shni_config
import shni_portscan
import shni_sniffing
import shni_logs
import shni_detection
import shni_virus
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

class shni():
	
	#PUBLIC VARS
	config = {}
	allowed_config_options = ['network', 'ports', 'scan_timeout']

	dashboard_values = {}
	
	ports = None
	backup_ports = None
	timeout = 1

	#check if user has hit ctrl-break
	interrupted = False

	#constructor method
	#def __init__(self);
		
	
	def initialise(self):
		self.load_ports()
		self.load_dashboard_values()


	#temporarily save current ports
	def tmp_save_ports(self):
		self.backup_ports = self.ports

	#reload tmp saved ports
	def tmp_load_ports(self):
		self.ports = self.backup_ports
		


	#method to set the network range
	def load_config(self):
		try:		
			self.config = {}
			#open the config file and load its settings
			f = open("shni.cfg", "rb")	
			lines = f.readlines()
			f.close()			
			for line in lines:
				if line[0] != '#':
					key, val = line.partition("=")[::2]
					if key.strip().lower() in self.allowed_config_options:
						self.config[key.strip().lower()] = val.strip()
		

			self.initialise()	
		except Exception, e:
			print "Load Config:: Exception: %s" %  e.message
			raw_input("debug: hit enter")
			pass
		
	
	def load_dashboard_values(self):
		if self.config_exist('network'):
			ip = IPNetwork(self.config['network'])
			self.dashboard_values['Total Hosts'] = len(list(ip))
			self.dashboard_values['Total Ports per host'] = len(self.ports)

	
	def get_dashboard_values(self):
		values = ""
		#get the longest key for printing purposes
		length = 0
		for key in self.dashboard_values:
			if len(key) > length:
				lenght = len(key)
		lenght += 2


		for key in self.dashboard_values:
			values += "%s:%s \n" % (key.ljust(length), self.dashboard_values[key]) 
		return values


	#test config items
	def config_exist(self, config_item):
		return config_item in self.config


	def view_network_details(self):
		if self.config_exist('network'):
			ip = IPNetwork(self.config['network'])
			os.system('clear')
			print "Shni - Network Details"
			print "===================="
			print ""
			print "IP             : %s" % ip
			print "IP version     : %s" % ip.version
			print "Total hosts    : %s" % len(list(ip))
			print "Broadcast      : %s" % ip.broadcast
			print "Netmask        : %s" % ip.netmask
			print "Hostmask       : %s" % ip.hostmask
			print "Network Bits   : %s" % ip.network.bits()
			print "Netmask Bits   : %s" % ip.netmask.bits()
			print "Broadcast Bits : %s" % ip.broadcast.bits()
			print "Is Multicast   : %s" % ip.is_multicast()
			print "Is Unicast     : %s" % ip.is_unicast()
			print "Is Private     : %s" % ip.is_private()
			print "Is Public      : %s" % (not ip.is_private())
			print "Is Reserved    : %s" % ip.is_reserved()
			print "Is Loopback    : %s" % ip.is_loopback()
			print " "
			raw_input("Press any key to continue")
					
		
	def view_network_ips(self):
		if self.config_exist('network'):
			ip = IPNetwork(self.config['network'])
			os.system('clear')
			print "Shni - Network IP's"
			print "===================="
			print ""
			print "IP             : %s" % ip
			print " " 
			print "Ips in Range: " 
			print "============= "
			for ip in list(ip):
				print ip
			
			print " "
			raw_input("Press any key to continue")
					
	

	#display config
	def view_config(self):
		os.system('clear')
		print "Shni - Config"
		print "==========="
		print ""
		
		count = 0
		for item in self.config:
			count += 1
			print "%s.%s: %s" % (count, item, self.config[item])

		print " "
		raw_input("Press any key to continue")


	def set_config(self, config_item):
		if self.config_exist(config_item):
			os.system('clear')
			print "Shni - Set Config"
			print "==========="
			print ""
			newval = raw_input("Set the new \"%s\" value: " % config_item) 
			self.config[config_item] = newval
			self.initialise()	
		
			
	def load_ports(self):
		#get the ports to be scanned
		if self.config_exist('ports'):
			portlst = []
			
			if self.config['ports'].strip().lower() == 'all':
				portlst =  range(1,65535)
			else:				
				tmp = self.config['ports'].split(",")
				for port in tmp:
					try:
						intport = int(port.strip())
						portlst.append(intport)
					except Exception, e:
						print "load_ports:: Exception: %s" % e.message
						pass

		if len(portlst)== 0:
			portlst =  range(1,65535)
		
		self.ports = portlst
		
	
	def view_ports(self):
			os.system('clear')
			print "Shni - Ports to scan"
			print "===================="
			print ""
			print "Ports in Range: " 
			print "============= "
			for port in self.ports:
				print port
			
			print " "
			raw_input("Press any key to continue")


	def port_scan_menu(self):
		shni_portscan.view_portscan_menu(self)
			
	def config_menu(self):
		shni_config.view_config_menu(self)
		
	def sniff_menu(self):
		shni_sniffing.view_sniffing_menu(self)
		
	def logs_menu(self):
		shni_logs.view_logs_menu()
		
	def virus_menu(self):
		shni_virus.view_virus_menu(self)
		
	def detection_menu(self):
		shni_detection.view_detection_menu(self)
		
	def interrupt_handler(self, signum, frame ):
		print("Custom interrupt detected...Function will be stopped shortly...")
		self.interrupted = True

			
				










