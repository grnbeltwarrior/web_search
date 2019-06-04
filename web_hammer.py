#!/usr/bin/python3

# Python script to consume the csv file that you can export from Metaploit. The script will bombard the ports identified in the csv file that match those in the nameList as well as 
# https://www.offensive-security.com/metasploit-unleashed/using-databases/#CSV_Export
# Then you can take the output of this script (web_hammer_output.txt) and feed it to EyeWitness.py

# import
import os
import sys
import csv
import subprocess
from subprocess import PIPE
import requests
from termcolor import colored
import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

timeOut = 0.5

vuln_links = ['jmx-console/',
'web-console/ServerInfo.jsp',
'invoker/JMXInvokerServlet',
'system/console',
'axis2/axis2-admin/',
'manager/html',
'tomcat/manager/html',
'wp-admin',
'workorder/FileDownload.jsp',
'ibm/console/logon.jsp',
'data/login',
'script/',
'opennms']

def webBuilder(ip,portColon,port,https):
	if (port == 80) and (https == False):
		urlHttp = 'http://' + ip
		webHammer(urlHttp)
	elif (port == 443) and (https == True):
		urlHttps = 'https://' + ip
		webHammer(urlHttps)
	else:
		urlHttp = 'http://' + ip + portColon + port
		urlHttps = 'https://' + ip + portColon + port
		webHammer(urlHttp)
		webHammer(urlHttps)

	for path in vuln_links:
		url = urlHttp + '/' + path
		webHammer(url)
		url = urlHttps + '/' + path
		webHammer(url)

def webHammer(url):
	try:
		print("URL tested in webHammer: " + url)
		data = requests.get(url, timeout=timeOut, verify=False, allow_redirects=True)
		print(data)
		if str(data.status_code) == '200':
			f.write(url + '\n')

	except requests.exceptions.Timeout:
		pass
		#print("The following URL timed out: " + url) #Uncomment these if you want the errors to go to the console.
	except requests.exceptions.RequestException as e:
		#pass
		print("The following error occurred: " + str(e)) #Uncomment these if you want the errors to go to the console.
		# pick up the ball from urllib3's issue with DH keys
		result = subprocess.Popen(["curl", "-vLk", "%s" % (url)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		output, errors = result.communicate()
		if ("HTTP/1.1 200 OK" in str(errors)):
			f.write(url + '\n')
		pass

def dictionaryWork(ip,port,name):
	#headers = {'User-Agent':'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0'} # not currently used.
	if ("https" in name) or ("ssl" in name):
		#http = "https"
		#port = port.split("/")[0]
		https = True
		if int(port) == 443:
			portColon = ''
			port = ''
		else:
			portColon = ':'
		webBuilder(ip,portColon,port,https)

	else:
		#http = "http"
		#port = port.split("/")[0]
		https = False
		if int(port) == 80:
			portColon = ''
			port = ''
		else:
			portColon = ':'
		webBuilder(ip,portColon,port,https)

def readCSV(file):
	print(colored('Reading in CSV...', 'green', attrs=['bold']))
	with open(file, newline='') as csvfile:
		csvRead = csv.reader(csvfile, delimiter=',')
		for row in csvRead:
			triggered = 0
			ip = row[0]
			port = row[1]
			protocol = row[2]
			name = row[3]
			state = row[4]
			#info = row[5] # not currently used forward.
			if (protocol == 'tcp') and (state == 'open'):
				print(row)
				for item in nameList:
					if (name == item) or ("ssl" in name):
						triggered =+ 1
				if triggered > 0:
					dictionaryWork(ip,port,name)
	csvfile.close()

def usage():
	print("Usage: web_search_services.py /path/to/file/services.csv")
	print()
	print("Example: ")
	print("web_search_services.py /home/grnbeltwarrior/services.csv")
	sys.exit()

try:
        file = sys.argv[1]

except IndexError:
	print("[-] Services.csv file path is needed")
	usage()

num = file.find("services")
path = file[0:num]
print(path)
output = path + 'web_hammer_output.txt'
print(output)
f = open(output, 'w+')

nameList = ["www", "http", "https", "upnp"]

readCSV(file)
f.close()
