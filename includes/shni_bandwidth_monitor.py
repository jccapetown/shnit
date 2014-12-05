#sniffing methods for shni
from scapy.all import *
import shni_sniffing_custom_filter
from collections import Counter,OrderedDict

def view_bandwidth_menu(shni):
	input = ""
	while input != 'x':

		os.system('clear')
		print "Sniffing"
		print "========"
		print "1. Monitor Ip Bandwidth"
		print ""
		print "x. Exit"
		input = raw_input("Select an option: ")
	
		#CONFIG 
		if str(input) == '1':
			monitor_packets(shni)


	
def monitor_packets(shni):
	os.system('clear')
	
	print "Checking Bandwidth Usage"
	print "========================"
	sample_interval = int(raw_input("Total seconds to inspect traffic: "))
	interface= raw_input("Interface: ")
	
	sfilter= raw_input("Filter: [all]: ")

	global verbose	
 	verbose = raw_input("Show traffic [y/n] ") == 'y'
		

	global traffic 
	traffic = Counter()
	# You should probably use a cache for your IP resolutions
	hosts = {}
	
	os.system("clear")
	print "Checking Bandwidth Usage"
	print "========================"
	print "Detail:"	
	sniff(iface=interface, prn=traffic_monitor_callback, store=False,timeout=sample_interval, filter=sfilter )
		# ... and now comes the second place where you're happy to use a
	# Counter!
	# Plus you can use value unpacking in your for statement.
	os.system('clear')
	print "Checking Bandwidth Usage"
	print "========================"
	print "Summary:"	
	print "Source".ljust(30), "Destination".ljust(30), "Total" 
	print ("="*6).ljust(30),  ("="*11).ljust(30), "="*5

	test = []
	for (h1, h2), total in traffic.most_common():
		test.append(total)
	
	list =  sorted(test, reverse=True)
	data = {}
	
	for i in list:
		for (h1, h2), total in traffic.most_common():
			if i == total:
				data[total] = (h1,h2)

	for total  in OrderedDict(data):
			h1, h2 = map(ltoa, data[total])
			print "%s%s%s - %s/s" % (h1[:28].ljust(30), h2[:28].ljust(30), human(total), human(float(total)/sample_interval)) 

	
	#for (h1, h2), total in traffic.most_common(20):
	#		# Let's factor out some code here
	#		h1, h2 = map(ltoa, (h1, h2))
#			for host in (h1, h2):
#					if host not in hosts:
#							try:
#									rhost = socket.gethostbyaddr(host)
#									hosts[host] = rhost[0]
#							except:
#									hosts[host] = None
			# Get a nice output
			
#			h1 = "%s (%s)" % (hosts[h1], h1) if hosts[h1] is not None else h1
#			h2 = "%s (%s)" % (hosts[h2], h2) if hosts[h2] is not None else h2
		#	print "%s/s: %s - %s" % (human(float(total)/sample_interval), h1, h2)
#			print "%s%s%s - %s/s" % (h1[:28].ljust(30), h2[:28].ljust(30), human(total), human(float(total)/sample_interval)) 
	raw_input("Continue")

def human(num):
		for x in ['', 'k', 'M', 'G', 'T']:
				if num < 1024.: return "%3.1f %sB" % (num, x)
				num /= 1024.
		# just in case!
		return	"%3.1f PB" % (num)

def traffic_monitor_callback(pkt):
		global traffic
		global verbose
		if IP in pkt:
				pkt = pkt[IP]
				# You don't want to use sprintf here, particularly as you're
				# converting .len after that!
				# Here is the first place where you're happy to use a Counter!
				# We use a tuple(sorted()) because a tuple is hashable (so it
				# can be used as a key in a Counter) and we want to sort the
				# addresses to count mix sender-to-receiver traffic together
				# with receiver-to-sender
				traffic.update({tuple(sorted(map(atol, (pkt.src, pkt.dst  )))): pkt.len})
				if verbose:
					print "%s%s%s" % (pkt.src[:28].ljust(30), pkt.dst[:28].ljust(30), human(pkt.len) ) 
		#else:
			#print pkt.summary()

