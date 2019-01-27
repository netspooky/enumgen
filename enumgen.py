import requests, base64, json, sys, argparse

# Arguments
parser = argparse.ArgumentParser(description='Enum Generator')
parser.add_argument("-H",dest='sHost',help='Box IP/Hostname',nargs='?')
parser.add_argument("-n",dest='sName',help='Box Name',nargs='?')
parser.add_argument("-o",dest='sOS',help='Box OS Version',nargs='?')
parser.add_argument("-g",dest='gen',help='What to generate. enum / cheat / postex',nargs='?')

args  = parser.parse_args()

# Run command like 
# enumgen.py -i <ip> -n <name> -o <OS> -g <enum/cheat>
# Then an if statement to handle other params
# Maybe toggle what scripts to generate. Can do cheatsheet, basic enum, and privesc. 
# Need a wordlist for cheatsheet
# Maybe flags like -ww for web wordlist



### Art Area
artPortScan = """
                              __                                        
        ______   ____________/  |_    ______ ____ _____    ____   ______
        \\____ \\ /  _ \\_  __ \\   __\\  /  ___// ___\\\\__  \\  /    \\ /  ___/
        |  |_> >  <_> )  | \\/|  |    \\___ \\\\  \\___ / __ \\|   |  \\\\___ \\ 
        |   __/ \\____/|__|   |__|   /____  >\\___  >____  /___|  /____  >
        |__|                             \\/     \\/     \\/     \\/     \\/
        ---  Put Nmap, Unicorn Scan, or other scans you want handy  ---
"""

artServices = """
                                        .__                     
                ______ ______________  _|__| ____  ____   ______
               /  ___// __ \\_  __ \\  \\/ /  |/ ___\\/ __ \\ /  ___/
               \\___ \\\\  ___/|  | \\/\\   /|  \\  \\__\\  ___/ \\___ \\ 
              /____  >\\___  >__|    \\_/ |__|\\___  >___  >____  >
                   \\/     \\/                    \\/    \\/     \\/ 
               -- List Ports You Find here with some notes! ---
For each port, XX == port num.
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                             versions! cves?? │
└──[∙ Port Service Type ∙]──────────────────────────────────────────────[ XX ]─┘
┌──────────────────────────────────────────────────────────────────────────────┐
└──[∙ Possible Attack Vectors  ∙]───────────────────────────────────────[ XX ]─┘
┌──────────────────────────────────────────────────────────────────────────────┐
└──[∙ Things that didnt work ∙]─────────────────────────────────────────[ XX ]─┘
────────────────────────────────────────────────────────────────────────────────

"""

artWebServer = """
                       ___.  
         __  _  __ ____\\_ |__     ______ ______________  __ ___________ 
         \\ \\/ \\/ // __ \\| __ \\   /  ___// __ \\_  __ \\  \\/ // __ \\_  __ \\
          \\     /\\  ___/| \\_\\ \\  \\___ \\\\  ___/|  | \\/\\   /\\  ___/|  | \\/
           \\/\\_/  \\___  >___  / /____  >\\___  >__|    \\_/  \\___  >__|   
                      \\/    \\/       \\/     \\/                 \\/    
┌──────────────────────────────────────────────────────────────────────────────┐
└──[∙ Server Version ∙]────────────────────────────────────────────────────────┘
┌──────────────────────────────────────────────────────────────────────────────┐
└──[∙ What's On index.html? ∙]─────────────────────────────────────────────────┘
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                      types! versions! cves?? │
└──[∙ Web Technologies ∙]──────────────────────────────────────────────────────┘
┌──────────────────────────────────────────────────────────────────────────────┐
│                                 view-source: anything internal? dir listing? │
└──[∙ Interesting URLs ∙]──────────────────────────────────────────────────────┘
┌──────────────────────────────────────────────────────────────────────────────┐
│                     any names? references to functionality? other weirdness? │
└──[∙ Other Observations ∙]────────────────────────────────────────────────────┘
▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
█┌────────────────────────────────────────────────────────────────────── ─∙··· █
█│                             S C A N  O U T P U T                           │█
█ ···∙─ ──────────────────────────────────────────────────────────────────────┘█
▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀ 
▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ EOF ▄▄▄
┌──────────────────────────────────────────────────────────────────────────────┐
└──[∙ Possible Attack Vectors  ∙]──────────────────────────────────────────────┘
┌──────────────────────────────────────────────────────────────────────────────┐
└──[∙ Things that didnt work ∙]────────────────────────────────────────────────┘
┌───────────────────────────────[∙ Work Space ∙]───────────────────────────────┐
│ ██▓▓▒▒░░           For everything else, enumerate here!             ░░▒▒▓▓██ │
└──────────────────────────────────────────────────────────────────────────────┘
"""

artEnumNotes = """
                                       __                 
                          ____   _____/  |_  ____   ______
                         /    \\ /  _ \\   __\\/ __ \\ /  ___/
                        |   |  (  <_> )  | \\  ___/ \\___ \\ 
                        |___|  /\\____/|__|  \\___  >____  >
                             \\/                 \\/     \\/
          --- Keep track of yr thoughts as you go through your scan. ---
          --- Especially after you try a new thing or hit milestone! ---


             .__                              __                 __   
             |__| _____ ______   ____________/  |______    _____/  |_ 
             |  |/     \\\\____ \\ /  _ \\_  __ \\   __\\__  \\  /    \\   __\\
             |  |  Y Y  \\  |_> >  <_> )  | \\/|  |  / __ \\|   |  \\  |  
             |__|__|_|  /   __/ \\____/|__|   |__| (____  /___|  /__|  
                      \\/|__|                           \\/     \\/     
             -- Put creds, commands, and other important info here! --
"""


artCheatsheet = """$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
    _________ .__                   __   _________.__                   __   
    \\_   ___ \\|  |__   ____ _____ _/  |_/   _____/|  |__   ____   _____/  |_ 
    /    \\  \\/|  |  \\_/ __ \\\\__  \\\\   __\\_____  \\ |  |  \\_/ __ \\_/ __ \\   __\\
    \\     \\___|   Y  \\  ___/ / __ \\|  | /        \\|   Y  \\  ___/\\  ___/|  |  
     \\______  /___|  /\\___  >____  /__|/_______  /|___|  /\\___  >\\___  >__|  
            \\/     \\/     \\/     \\/            \\/      \\/     \\/     \\/     
$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$"""

def genEnum():
	# Writing host.txt with hostname or IP
	f = open('host.txt','w')
	f.write(sHost)
	f.close()

	# Meta Information

	mInfo = ["[ Box IP.... ] ","[ Box Name.. ] ","[ OS Version ] "]

	print("[+] Generating Enum File with the following info:\n")
	print(mInfo[0] + sHost)
	print(mInfo[1] + sName)
	print(mInfo[2] + sOS)



	# TODO - Generate ip.txt with just the IP in case some script like sniper needs

	### enum.txt
	# Refer to this https://sites.google.com/site/yuuoscp/stuff-to-revisit/stuff
	# Enum in general should ask specific questions, with the corresponding commands in cheatsheet.txt
	# Make a handy templated text file that asks questions about services and helps the attacker 
	# understand what they are looking for.
	# Ask what services there are!
	# 
	# Also tell them to run everything in screen with script!
	# screen 
	# script
	# then exit script with exit to stop logging
	# ctrl a ctrl d to detach from screen

	### Other things to keep track of 
	# - Software + Version
	# - General Services Open
	# - It's place on the network (eg wireshark sniffing, domain info etc)
	# - Important creds - keep in a specific creds section at the bottom!
	# 
	# Have it generate an enum, privesc, and cheatsheet file
	# - $NAME_enum.txt enum will have all these basic things and keeping track of them
	#   Should def leverage pyfiglet for section header names :D
	# - $NAME_privesc.txt privesc will be for post exploitation
	# - $NAME_cheatsheet.txt cheatsheet will have all the other commands for random services 
	#   instead of putting in enum.txt. Maybe would be good to generate HTML instead of TXT
	# ? What if I also have a tool searcher too, like with blackarch but just every tool in there and links.
	# 
	# Put in techniques too
	# find . -type f -name "*.java" -exec grep -il 'foo' {} \;

	### Nmap Templates
	# Perhaps could include more exotic command templates.
	nmapTemplates = [
	    "nmap --top-ports=100 ",
	    "nmap -sC -sV ",
	    "nmap -vv -Pn -A -sS -T 4 -p- ",
	    "nmap -sU "
	    ]

	nImpatient    = nmapTemplates[0] + "-oN " + sName + "_t100.nmap " + sHost
	nQuick        = nmapTemplates[1] + "-oN " + sName + "_qwik.nmap " + sHost
	nBrutal       = nmapTemplates[2] + "-oN " + sName + "_full.nmap " + sHost
	nUDP          = nmapTemplates[3] + "-oN " + sName + "_udp.nmap " + sHost

	print(artPortScan)
	print("[ Impatient ] " + nImpatient )
	print("[ Quick.... ] " + nQuick )
	print("[ Brutal... ] " + nBrutal )
	print("[ UDP...... ] " + nUDP )
	print("[!] Not sure what something is? Try amap!")

	print(artServices)
	print(artWebServer)
	print(artEnumNotes)
	# Should also add nmap script stuff too later.
	# Also put references to cheat sheets
	# http://repo.n0.lol/w/Nmap_Cheatsheet
	# https://highon.coffee/blog/nmap-cheat-sheet/


def genCheatSheet():
	### cheatsheet.txt / html
	# Cheatsheet should be a bunch of things that people commonly need to refer to.
	# Specific commands for attacking or enumming certain services.
	# Maybe can just have a way to specify which services you're targeting
	# Like maybe need to make a text file that this script can parse to properly generate a cheatsheet
	# eg: web server, ldap, kerberos, dns, ssh, telnet, ftp etc.
	#   Similar to how nmap outputs
	# Or you can do just based on nmap ports found?
	# It can parse a .nmap file or something idk. Instead of running with python nmap

	print(artCheatsheet)
	print("\n[+] Generating Web Enum commands for {}_cheatsheet.txt".format(sName))

	# List commands with just host
	def lCmd(cmdList):
	    for cmd in cmdList:
	        print("  "+cmd.format(sHost))
	### Generic Webserver Enum Commands
	# I wanna parameterize, but how can i do that with an array?
	# Because like, nikto does -host and -output which would hold the output in a text file
	# Also has Plugins too which would be optional.


	webEnum = [ "\n[ Web Enumeration ]",
	            "nikto -host {}",
	            "gobuster -w ~/git/SecLists/Discovery/Web-Content/big.txt -s '200,204,301,302,307,403,500' -e -fw -u http://{}",
	            "whatweb {}"
	    ]


	# Commands for quickly testing shit.
	# Should put in a dict or something with an explanation
	webTest = [ "\n[ Web Services Testing ]",
	            'curl -A "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" http://{}',
	            'curl -d "data=True" -X POST http://{}',
	            'More Info: https://gist.github.com/subfuzion/08c5d85437d5d4f00e58\n',
	            'sslscan {}:443',
	            'nmap -sV --script=ssl-heartbleed {}'
	          ]
	# Little things to remember
	webTrix = [ "\n[ Web Trixxx ] ",
	            "Bypass php execution\n    http://{}/index.php?page=php://filter/convert.base64-encode/resource=index",
	            "Then decode b64 output\n    base64 -d indexcoded",
	            "Pass a cookie with curl\n    curl -s http://{}/login.php -c cookie.txt -d 'user=admin&pass=admin'",
	            "  curl -s http://{}/somepage.php?page=/etc/passwd -b cookie.txt"
	]
	lCmd(webEnum)
	lCmd(webTest)
	lCmd(webTrix)

	### Service Enum Commands

	ftpEnum  = [ "\n[ FTP Enumeration - Port 21 ]",
	             "ftp {}",
	             "nc {} 21",
	             "hydra -t 1 -L users.txt -P passlist.txt {} ftp",
	             "nmap --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 {}",
	             "Don't forget BINARY / ASCII modes!"
	           ]

	sshEnum  = [ "\n[ SSH Enumeration - Port 22 ]",
	             "hydra -t 4 -L users.txt -P passlist.txt {} ssh",
	             "nmap -v -p 22 --script=ssh2-enum-algos.nse,ssh-hostkey.nse,sshv1.nse --script-args=unsafe=1 {}"
	           ]

	telnetEnum = ["\n[ Telnet Enum - Port 23 ]",
	             "hydra -l root -P ~/SecLists/Passwords/10_million_password_list_top_100.txt {} telnet"
	             ]

	smtpEnum = [ "\n[ SMTP Enumeration - Port 25 ]",
	             "telnet {} 25",
	             "nmap -script smtp-commands.nse {}",
	             "smtp-user-enum -M VRFY -U usernames.txt -t {}"
	           ]

	snmpEnum = [ "\n[ SNMP Enumeration - Port 161 ]",
	             "snmpwalk -c public -v1 {}",
	             "snmpcheck -t {} -c public",
	             "onesixtyone {} public",
	             "python /usr/share/doc/python-impacket-doc/examples/samrdump.py SNMP {}",
	             "snmpenum -t {}"
	           ]

	smbEnum  = [ "\n[ SMB Enumeration - Port 139/445 ]",
	             "enum4linux -a {}",
	             "nmap -p 139,445 --script=smb-* {}",
	             "smbclient -L {}",
	             "smbclient {} <sharename> -U guest",
	             "showmount -e {}",
	             "mount {}:/share /mnt/nfs -nolock",
	             "mount -t cifs -o user=USERNAME,sec=ntlm,dir_mode=0077 '//{}/My Share' /mnt/cifs",
	             "rpcclient -U '' {}"
	           ]
	ldapEnum = [ "\n[ LDAP Enumeration - Port 339/636 ]",
	             'ldapsearch -h 192.168.1.101 -p 389 -x -b "dc=mywebsite,dc=com"'
	           ]
	nfsEnum  = [ "\n[ NFS Enumeration - Portt 2049 ]",
	             "showmount -e {}",
	             "mount -t {}:/ /tmp/nfs"
	           ]

	sqlEnum  = [ "\n[ SQL Enumeration - Port 3306 ]",
	             "nmap -sV -sC -Pn -p3306 --script=mysql-vuln-cve2012-2122,mysql-query,mysql-enum {}",
	             "nmap -sV -Pn -p3306 --script=mysql-variables,mysql-users,mysql-empty-password,mysql-databases,mysql-brute {}",
	             "nmap -p3306 --script=mysql-dump-hashes --script-args='username=root,password=root' {}",
	             "mysql -h {} -u root",
	             "mysql -h {} -u root@localhost"
	           ]
	rdpEnum  = [ "\n[ RDP Enum ]",
	             "rdesktop -u guest -p guest {} -g 94%",
	             "ncrack -vv --user Administrator -P /root/passwords.txt rdp://{}"
	            ]
	print("\n[+] Generating Service Enum Commands for {}_cheatsheet.txt".format(sName))
	lCmd(ftpEnum)
	lCmd(sshEnum)
	lCmd(telnetEnum)
	lCmd(smtpEnum)
	lCmd(snmpEnum)
	lCmd(smbEnum)
	lCmd(ldapEnum)
	lCmd(nfsEnum)
	lCmd(sqlEnum)
	lCmd(rdpEnum)

	sqlCheat = "    show databases;\n    use dbname;\n    show tables;\n    select * from tablename;\n\n    Also possibly check for udf vuln!"
	print("\n[+] When logged into mySQL")
	print(sqlCheat)


### PostExploitation
# need to be os specific
# things like reverse shells, sandbox escape, general one liners 

def genPostex():
	if sOS == "windows":
		print("\n[ Windows Cheat Sheet!]")
	if sOS == "linux":
		print("\n[ Linux Cheat Sheet!]")
	else:
		print("No OS defined. Pass the -o flag with <linux/windows>")
		exit()


# Checking Vars
if args.sHost:
    sHost = args.sHost
else:
    print("Box IP Required! use flag -H <ip/hostname>")
    exit()
if args.sName:
    sName = args.sName
else:
    print("Box Name Required! use flag -n <box name>.")
    exit()
if args.sOS:
    sOS = args.sOS
else:
    print("[!] No OS defined, creating generic output. Run again with -o flag to generate privesc info")
    sOS = ""
if args.gen == "enum":
	genEnum()
if args.gen == "cheat":
	genCheatSheet()
if args.gen == "postex":
	genPostex()
