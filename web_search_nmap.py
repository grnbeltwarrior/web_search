#!/usr/bin/python

# import
import os
import sys
import socket
import getopt
import threading
import subprocess
import requests
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()

https = False
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
'ibm/console/logon.jsp?action=OK',
'data/login',
'script/',
'opennms']

new_buffer = 0

def IPGet(line):
        ip = line.split(" ")[-1]
        ip = ip.strip("(")
        ip = ip.strip(")")
        #print ip
        return ip

def doWork(old_ip, line):
        ports = []
        global d
        while "  " in line:
                line = line.replace("  "," ");
        linesplit = line.split(" ")
        service = linesplit[2]
        port = linesplit[0]
        if service in d:
                ports = d[service]
        ports.append(port)
        d[service] = ports

def webHammer(ip,http,portColon,port):
	url = http + '://' + ip + portColon + port
	#print url
	fruitHammer(url)
	for path in vuln_links:
		url = http + '://' + ip + portColon + port + '/' + path
		#print url
		fruitHammer(url)

def fruitHammer(url):
	#headers = {'User-Agent':'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0'}
	try:
		data = requests.get(url, timeout=timeOut, verify=False, allow_redirects=True)
		#print data.url
		#print data.history
		#print data.status_code
		if str(data.status_code) == '200':
			print "The following URL returned a status of OK: " + url
			#print data.text + '\r\n'
	except requests.exceptions.Timeout:
		pass
		#print "The following URL timed out: " + url #Uncomment these if you want the errors to go to the console.
	except requests.exceptions.RequestException as e:
		pass
		#print "The following error occurred: " + e #Uncomment these if you want the errors to go to the console.

def dictionaryWork(ip,d):
        #print "[+] Dictionary Keys for IP: " + str(ip)
        #print d
	headers = {'User-Agent':'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0'}
        for serv in d:
                ports = d[serv]
	        if ("http" in serv) and ("https" not in serv):
        	        for port in ports:
                	        #print "[+] HTTP Port: " + port
				http = "http"
	                        port = port.split("/")[0]
				if int(port) == 80:
					portColon = ''
					port = ''
				else:
					portColon = ':'
				webHammer(ip,http,portColon,port)

	        if ("https" in serv) or ("ssl/http" in serv):
        	        for port in ports:
                	        #print "[+] HTTPS Port: " + port
				http = "https"
                        	port = port.split("/")[0]
				if int(port) == 443:
					portColon = ''
					port = ''
				else:
					portColon = ':'
				webHammer(ip,http,portColon,port)

		if ("tcpwrapped" in serv) or ("possible_wls" in serv):
			for port in ports:
				#print "[+] TCPWrapped Port: " + port
				http = 'http'
				portColon = ':'
				port = port.split("/")[0]
				webHammer(ip,http,portColon,port)


def resetVars():
        global d
        d = {}
        global ports
        ports = []
        global host_ip
        host_ip = ""

def usage():
	print "Usage: web_search_nmap.py /path/to/nmap/file"
	print
	print "Example: "
	print "web_search_nmap.py /home/grnbeltwarrior/Engagement/nmap"
	sys.exit()

try:
        carPath = sys.argv[1]

except IndexError:
	print "[-] Nmap file path is needed"
	usage()

# file access work
for file in os.listdir(carPath):
        if file.endswith(".nmap"):
                filePath = os.path.join(carPath, file)
        if file.endswith(".xml"):
                xmlPath = os.path.join(carPath, file)

file = open(filePath,'r')

d = {}
num_hosts = 0
host_ip = ""

for line in file.readlines():
        line = line.strip()
        #host_ip = ""
        old_ip = ""
        if ("Nmap scan report for" in line) or ("Service detection performed" in line):
                if "Service detection performed" in line:
                        old_ip = host_ip
                        dictionaryWork(old_ip,d)
                        break
                if num_hosts > 0:
                        old_ip = host_ip
                        dictionaryWork(old_ip,d)
                        resetVars()
                        host_ip = IPGet(line)
                        num_hosts = num_hosts + 1
                else:
                        host_ip = IPGet(line)
                        num_hosts = num_hosts + 1
        else:
                if ("/tcp" in line) and ("open" in line) and not ("Discovered" in line):
                        doWork(host_ip, line)

file.close()
