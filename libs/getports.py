from netaddr import * #pip
import threading, socket, json
from . import getauthenticationmethod as getAUTH
from colorama import init
from termcolor import colored
import masscan #pip
import logging

init()

portList = [554, 555, 5544, 5554, 8554, 1554] # Other commong RTSP ports: 555, 8554, 1554, 7070, 1935, 10554
targetList = dict()

def masscan_target(iprange):
    print(colored("[*] Discovering targets. Please wait...", 'yellow'))
    try:
        converted_list = [str(element) for element in portList]
        ports = ','.join(converted_list)
        mas = masscan.PortScanner()
        mas.scan(iprange, ports=ports, arguments='--max-rate 100000')
        for ipaddress in mas.scan_result["scan"]:
            for portfound in mas.scan_result["scan"][ipaddress]["tcp"]:
                if str(ipaddress) not in targetList:
                    targetList[str(ipaddress)] = dict({portfound: getAUTH.detect_auth(ipaddress, portfound)})
                else:
                    targetList[str(ipaddress)].update({portfound: getAUTH.detect_auth(ipaddress, portfound)})
    except:
        pass

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

# masscan_target("79.129.126.104/18")