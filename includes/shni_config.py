#Config module for the shni framework
import os
def view_config_menu(shni):
		input = ""
		while input != 'x':

			os.system('clear')
			print "Config"
			print "===="
			print "vc. View Config"
			print "nd. Network Details"
			print "ni. Network Ips"
			print "vp. view ports"
			print "cn. Change network range/ip"
			print "cp. Change ports"
			print "ct. Change scan timeout"
			print "rc. Reload Config"
			print ""
			print "x. Exit"
			input = raw_input("Select an option: ")
	
			#CONFIG 
			if str(input) == 'vc':
				shni.view_config()
	
			if str(input) == 'nd':
				shni.view_network_details()
	
			if str(input) == 'ni':
				shni.view_network_ips()
	
			if str(input) == 'vp':
				shni.view_ports()
	
			if str(input) == 'cn':
				shni.set_config('network')
				dashboardvals = shni.get_dashboard_values()

			if str(input) == 'cp':
				shni.set_config('ports')
				dashboardvals = shni.get_dashboard_values()
			
			if str(input) == 'ct':
				shni.set_config('scan_timeout')
				dashboardvals = shni.get_dashboard_values()
	
	
			if str(input) == 'rc':
				shni.load_config()
	
			if str(input) == 'x':
				break;


