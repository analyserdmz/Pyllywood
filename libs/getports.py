# Custom port scanner
# In future versions, masscan will be used for faster and more accurate port-scans

from netaddr import * #pip
import threading, socket
from . import getauthenticationmethod as getAUTH
from colorama import init
from termcolor import colored

init()

portList = [554, 555, 5544, 5554, 8554, 1554] # Other commong RTSP ports: 555, 8554, 1554, 7070, 1935, 10554
targetList = dict()

def scan_target(ipaddress, portnumber, timeout=1):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        con = s.connect((socket.gethostbyname(str(ipaddress)),portnumber))
        if str(ipaddress) not in targetList:
            targetList[str(ipaddress)] = dict({portnumber: getAUTH.detect_auth(ipaddress, portnumber)})
        else:
            targetList[str(ipaddress)].update({portnumber: getAUTH.detect_auth(ipaddress, portnumber)})
        con.close()
    except:
        pass

def discover(cidr):
    print(colored("[*] Discovering targets. Please wait...", 'yellow'))
    net4 = IPNetwork(cidr)
    for target in net4:
        for port in portList:
            thread = threading.Thread(target = scan_target, args = (target, port))
            thread.start()
            if threading.active_count() == 1000:
                thread.join()
