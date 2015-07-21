#sniffing methods for shni
from scapy.all import *
import shni_sniffing_custom_filter
from collections import Counter,OrderedDict
import readline
import signal
import sys
import signal

def signal_handler(signal, frame):
        print('You pressed Ctrl+C!')
        sys.exit(0)

def view_bandwidth_menu(shni):
	input = ""
	while input != 'x':

		os.system('clear')
		print "Shni - Bandwidth Monitoring"
		print "==========================="
		print "1. Monitor Ip Bandwidth"
		print "2. Monitor Port Bandwidth"
		print ""
		print "x. Exit"
		input = raw_input("Select an option: ")
	
		#CONFIG 
		if str(input) == '1':
			monitor_packets(shni)
		if str(input) == '2':
			monitor_portpackets(shni)


	
def monitor_packets(shni):
	os.system('clear')
	
	print "Checking Bandwidth Usage"
	print "========================"
	#sample_interval = int(raw_input("Total seconds to inspect traffic: "))
	#interface= raw_input("Interface: ")
	
	sfilter= raw_input("Filter: [all]: ")
	global packetcount
	packetcount = 0
	global verbose	
 	verbose = raw_input("Show traffic [y/n] ") == 'y'
		

	global traffic 
	traffic = Counter()
	# You should probably use a cache for your IP resolutions
	hosts = {}

	try:
		os.system("clear")
		print "Checking Bandwidth Usage"
		print "========================"
		print "Gathering:"	
		#sniff(iface=interface, prn=traffic_monitor_callback, store=False,timeout=sample_interval, filter=sfilter )
		sniff(prn=traffic_monitor_callback, store=False, filter=sfilter)
		# ... and now comes the second place where you're happy to use a
		# Counter!
		# Plus you can use value unpacking in your for statement.
	except:
		pass


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
	
	top_records = 10

	for xcount, i in enumerate(list):
		if xcount >= top_records:
			break
		for (h1, h2), total in traffic.most_common(500):
			if i == total:
				h1, h2 = map(ltoa, (h1,h2))
				print "%s%s%s" % (h1[:28].ljust(30), h2[:28].ljust(30),human(total)) 

	print ""
	print "Total Packets Sniffed: %s" % packetcount
	raw_input("Continue")




def human(num):
		for x in ['', 'k', 'M', 'G', 'T']:
				if num < 1024.: return "%3.1f %sB" % (num, x)
				num /= 1024.
		# just in case!
		return	"%3.1f PB" % (num)



def traffic_monitor_callback(pkt):
		global packetcount
		global traffic
		global verbose
		dport = "?"
		sport = "?"
		if IP in pkt:
				pkt = pkt[IP]
				packetcount += 1

				traffic.update({tuple(sorted(map(atol, (pkt.src, pkt.dst )))): pkt.len})
				if verbose:
					print "%s%s%s" % (pkt.src[:28].ljust(30),  pkt.dst[:28].ljust(30), human(pkt.len) ) 



def monitor_portpackets(shni):
	os.system('clear')
	
	print "Checking Port Bandwidth Usage"
	print "============================="
	sport= raw_input("port [all]: ")	
	global packetcount
	packetcount = 0

	global portdict
	portdict = {}
	hosts = {}
	
	os.system("clear")
	print "Checking Ports Usage"
	print "===================="
	print "Gathering port trffic information:"	
	#sniff(iface=interface, prn=traffic_monitor_callback, store=False,timeout=sample_interval, filter=sfilter )
	if sport.strip() == '':
		#sfilter = "port 21"
		sfilter = ""
	else:
		sfilter = "port %s" % int(sport)

	try:

		sniff(prn=traffic_port_monitor_callback, store=False, filter=sfilter)
	except KeyboardInterrupt:
                pass
	# ... and now comes the second place where you're happy to use a
	# Counter!
	# Plus you can use value unpacking in your for statement.
	os.system('clear')
	print "Checking Port Bandwidth Usage"
	print "============================="
	print "Summary:"	

	#get the information from the group	
	tmpdict = {}
	for i in portdict:
		srcip,srcport,dstip, dstport,pktlen,pktdata = portdict[i]
		if not (srcip,dstip,dstport) in tmpdict:
			tmpdict[(srcip,dstip,dstport)] = {}
			tmpdict[(srcip,dstip,dstport)]['pktlen'] = 0
			tmpdict[(srcip,dstip,dstport)]['data'] = ''
			tmpdict[(srcip,dstip,dstport)]['totalpkts'] = 0
	
		tmpdict[(srcip,dstip,dstport)]['srcip'] = srcip
		tmpdict[(srcip,dstip,dstport)]['dstip'] = dstip
		tmpdict[(srcip,dstip,dstport)]['dstport'] = dstport
		tmpdict[(srcip,dstip,dstport)]['pktlen'] += pktlen
		tmpdict[(srcip,dstip,dstport)]['totalpkts'] += 1
		#tmpdict[(srcip,dstip,dstport)]['data'] = '%s%s' % ( tmpdict[(srcip,dstip,dstport)]['data'], pktdata  )
	
	tmpdict = sorted(tmpdict.items(), key = lambda x: x[1]['pktlen'], reverse=True)
	
	print "Source".ljust(30), "Destination".ljust(30), "Port".ljust(7), "Size".ljust(10), "Packets"
	print ("="*6).ljust(30),  ("="*11).ljust(30), ("="*4).ljust(7), ("="*4).ljust(10), "="*7
	for ix,i in  enumerate(tmpdict):
		print i[1]['srcip'].ljust(30), i[1]['dstip'].ljust(30), str(i[1]['dstport']).ljust(7),  human(i[1]['pktlen']).ljust(10), str(i[1]['totalpkts']).ljust(7) 
		#print ' ->', i[1]['data'] 
		if ix > 14: 
			break;


	print ""
	raw_input("Continue")


def traffic_port_monitor_callback(pkt):
		global packetcount
		global portdict
		dport = 0
		sport = 0
		dstip = 'Unknown'
		srcip = "Unknown"
		pktlen = 0
		if IP in pkt:
			srcip = pkt[IP].src
			dstip = pkt[IP].dst
			pktlen = pkt[IP].len
			
			if UDP in pkt:
				dport = pkt[UDP].dport
				sport = pkt[UDP].sport
				proto = "UDP"
					
			if TCP in pkt:
				dport = pkt[TCP].dport
				sport = pkt[TCP].sport
				proto = "TCP"
			
			data = ''
			if Raw in pkt:
				data = pkt[Raw]
			
			packetcount += 1
	
			portdict[packetcount] = (srcip,sport,dstip, dport,pktlen, data)   
			
			print "%s:%s\t\t\t %s:%s \t  (Total bytes: %s)" % (srcip,sport,dstip, dport,pktlen)	
			
