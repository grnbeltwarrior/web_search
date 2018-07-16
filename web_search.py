#!/usr/bin/python

# import
import sys
import os
import subprocess

def IPGet(line):
        print "[+] IP address: "
        ip = line.split(" ")[5]
        ip = ip.strip("(")
        ip = ip.strip(")")
        print ip
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

def dictionaryWork(ip,d):
        # searchsploit
        # os.system("searchsploit -v --nmap %s" % xmlPath)
        # print dictionary
        print "[+] Dictionary Keys for IP: " + str(ip)
        print d
        for serv in d:
        # print "[+] Service: " + serv
                ports = d[serv]
	        if ("http" in serv) and ("https" not in serv):
        	        for port in ports:
                	        print "[+] HTTP Port: " + port
	                        port = port.split("/")[0]
				print "Running Nikto and dirb Scan on : %s:%s" % (ip,port)
	                        os.system("nikto -h http://%s:%s" % (ip, port))
				os.system("dirb http://%s:%s -S" % (ip, port))
	        if ("https" in serv) or ("ssl/http" in serv):
        	        for port in ports:
                	        print "[+] HTTPS Port: " + port
                        	port = port.split("/")[0]
				print "Running Nikto and dirb Scan on : %s:%s" % (ip,port)
                        	os.system("nikto -h https://%s:%s" % (ip, port))
                        	os.system("dirb https://%s:%s -S" % (ip, port))
		if ("tcpwrapped" in serv) or ("possible_wls" in serv):
			for port in ports:
				print "[+] TCPWrapped Port: " + port
				port = port.split("/")[0]
				print "Running Nikto and dirb Scan on : %s:%s" % (ip,port)
				os.system("nikto -h http://%s:%s" % (ip, port))
                        	os.system("dirb http://%s:%s -S" % (ip, port))
				os.system("nikto -h https://%s:%s" % (ip, port))
                        	os.system("dirb https://%s:%s -S" % (ip, port))
        print "\n"

def resetVars():
        #print "Reset triggered"
        global d
        d = {}
        global ports
        ports = []
        global host_ip
        host_ip = ""

try:
        carPath = sys.argv[1]

except IndexError:
        print "[-] Nmap file path is needed"
        print "Example: search.py ./test/test/nmap"
        sys.exit(-1)

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
