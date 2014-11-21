#!/usr/bin/python
from includes.shni import shni as shniclass
#from netaddr import *
import os



#check if a network range has been defined
def initialise():
	#here we create the globally accessible class
	shni = shniclass()
	shni.load_config()
	return shni




def run(shni):
	dashboardvals = shni.get_dashboard_values()
	while 1==1:
		os.system('clear')			
		print "SHNI " 
		print "----"
		print ""
		print "Configured for %s" % shni.config['network']		
		print dashboardvals
		print ""
		print ""
		print "Menu"
		print "===="
		print "1. Config"		
		print "2. Port Scans"
		print "3. Sniffing"
		print "4. Logs"
		print ""
		print "x. Exit"
		input = raw_input("Select an option: ")


		#Actions
		if str(input) == '1':
			shni.config_menu()
		if str(input) == '2':
			shni.port_scan_menu()
		if str(input) == '3':
			shni.sniff_menu()
		if str(input) == '4':
			shni.logs_menu()
		if str(input) == 'x':
			break;
		
 
			
shni = initialise()
run(shni)






