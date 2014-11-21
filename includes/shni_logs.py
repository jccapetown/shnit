#Shni logs methods for shni framework
import os
import glob
def view_logs_menu():
		logs = load_logs()
		input = ""
		while input != 'x':
			os.system('clear')
			print "Logs"
			print "===="
			for itemtuple in logs:
				print "%s. %s" % (itemtuple[0],itemtuple[1])

			print ""
			print "x. Exit"
			input = raw_input("Select an option: ")
			
			for item in logs:
				if item[0]==input:
					os.system("cat %s" % item[1])
					raw_input("Back to menu")

			
	
			#Menu items 
			if str(input) == 'x':
				break
	
def load_logs():
	logs = []
	count = 0
	for file in glob.glob("logs/*.*"):
		count += 1
		logs.append( (str(count),file) )
	return logs


		
		
		
