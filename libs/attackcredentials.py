import socket, os, json, base64, hashlib
from libs import routebuilder
from libs import dealer
import sys, time

def describe(url, sequence, authSequence=None):
    msg = "DESCRIBE {} RTSP/1.0\r\n".format(url)
    msg += "CSeq: {}\r\n".format(sequence)
    if authSequence != None:
        msg += "Authorization: {}\r\n".format(authSequence)
    msg += "User-Agent: LibVLC/2.1.4 (LIVE555 Streaming Media v2014.01.21)\r\n"
    msg += "Accept: application/sdp\r\n"
    msg += "\r\n"
    return msg.encode()

def generateAuthString(username, password, realm, method, uri, nonce):
    mapRetInf = {}
    m1 = hashlib.md5("{}:{}:{}".format(username, realm, password).encode()).hexdigest()
    m2 = hashlib.md5("{}:{}".format(method, uri).encode()).hexdigest()
    response = hashlib.md5("{}:{}:{}".format(m1, nonce, m2).encode()).hexdigest()

    mapRetInf = "Digest "
    mapRetInf += "username=\"{}\", ".format(username)
    mapRetInf += "realm=\"{}\", ".format(realm)
    mapRetInf += "algorithm=\"MD5\", "
    mapRetInf += "nonce=\"{}\",".format(nonce)
    mapRetInf += "uri=\"{}\", ".format(uri)
    mapRetInf += "response=\"{}\"".format(response)
    return mapRetInf

def authBuilder(authMethod, buffer, username, password, uri):
    if authMethod == "Basic":
        authSeq = base64.b64encode("{}:{}".format(username, password).encode()).decode()
        authSeq = "Basic {}".format(authSeq)
        return authSeq
    else: # digest
        start = buffer.find("realm")
        begin = buffer.find("\"", start)
        end = buffer.find("\"", begin + 1)
        realm = buffer[begin+1:end]
        start = buffer.find("nonce")
        begin = buffer.find("\"", start)
        end = buffer.find("\"", begin + 1)
        nonce = buffer[begin+1:end]
        authSeq = generateAuthString(username, password, realm, "DESCRIBE", uri, nonce)
        return authSeq

def start(target, port, authmethod, foundRoutes=[]):
    with open(os.path.join(os.path.dirname(__file__), 'resources\\creds.json'), 'r') as f:
        userpasslist = json.load(f)

    if len(foundRoutes) > 0: # Found streams from route-first devices
        finalRet = [] # Final return with stream URLs
        authDetected = dealer.decide(target, port, foundRoutes[0]) # Detect auth method since here we got only "None" auth
        foundUser = ""
        foundPassword = ""

        try:
            # We connect to the target in a loop (some DIGEST AUTH devices terminate the connection if a route is found)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(20) # We allow 3 seconds of timeout
            sock.connect((target, port)) # Double parenthesis required
            sequence = 1 # Starting request sequence (needed in each request)
        except:
            return

        for user in userpasslist['usernames']:
            if len(finalRet) > 0:
                continue
            for pwd in userpasslist['passwords']:
                if len(finalRet) > 0:
                    continue
                try:
                    recBuffer = ""
                    digestBuffer = ""

                    if authDetected == "Digest":
                        # Get digest response (nonce, realm etc)
                        descURL = "rtsp://{}:{}/{}".format(target, port, foundRoutes[0].replace("invalidusername", user).replace("invalidpassword", pwd))
                        sock.send(describe(descURL, sequence))
                        digestBuffer = sock.recv(1024).decode()
                        sequence += 1
                    else:
                        descURL = "rtsp://{}:{}@{}:{}/{}".format(user, pwd, target, port, foundRoutes[0].replace("invalidusername", user).replace("invalidpassword", pwd))

                    sock.send(describe(descURL, sequence, authBuilder(authDetected, digestBuffer, user, pwd, "/{}".format(foundRoutes[0].replace("invalidusername", user).replace("invalidpassword", pwd)))))
                    recBuffer = sock.recv(1024).decode() # Receive the response
                    sequence += 1

                    if "RTSP/1.0 200" in recBuffer:
                        foundUser = user
                        foundPassword = pwd

                        for route in foundRoutes: # For each (probably) valid route
                            # sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            # sock.settimeout(20)
                            # sock.connect((target, port))

                            if authDetected == "Digest":
                                # Get digest response (nonce, realm etc)
                                descURL = "rtsp://{}:{}/{}".format(target, port, "/{}".format(route))
                                sock.send(describe(descURL, sequence))
                                digestBuffer = sock.recv(1024).decode()
                                sequence += 1
                            else:
                                descURL = "rtsp://{}:{}@{}:{}/{}".format(foundUser, foundPassword, target, port, "/{}".format(route))

                            sock.send(describe(descURL, sequence, authBuilder(authDetected, digestBuffer, foundUser, foundPassword, "/{}".format(route))))
                            recBuffer = sock.recv(1024).decode() # Receive the response
                            sequence += 1

                            if "RTSP/1.0 200" in recBuffer:
                                finalRet.append("rtsp://{}:{}@{}:{}/{}".format(foundUser, foundPassword, target, port, "/{}".route))
                except:
                    continue
        return finalRet
    else: # Here's credentials attack first (without a valid route)
        finalRet = dict() # Final return with stream URLs

        try:
            # We connect to the target in a loop (some DIGEST AUTH devices terminate the connection if a route is found)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(20) # We allow 3 seconds of timeout
            sock.connect((target, port)) # Double parenthesis required
            sequence = 1 # Starting request sequence (needed in each request)
        except:
            return

        for user in userpasslist['usernames']:
            for pwd in userpasslist['passwords']:
                try:
                    recBuffer = ""
                    digestBuffer = ""

                    if authmethod == "Digest":
                        descURL = "rtsp://{}:{}/gerghertherthrteh".format(target, port)
                        # Get digest response (nonce, realm etc)
                        sock.send(describe(descURL, sequence))
                        digestBuffer = sock.recv(1024).decode()
                        sequence += 1
                    else: # Basic authentication Describe URL
                        descURL = "rtsp://{}:{}@{}:{}/gerghertherthrteh".format(user, pwd, target, port)

                    sock.send(describe(descURL, sequence, authBuilder(authmethod, digestBuffer, user, pwd, descURL)))
                    recBuffer = sock.recv(1024).decode() # Receive the response
                    sequence += 1
                    # print(recBuffer)
                    if "RTSP/1.0 404" in recBuffer:
                        if target not in finalRet:
                            finalRet[target] = dict()
                        if port not in finalRet[target]:
                            finalRet[target][port] = dict()
                        finalRet[target][port][user] = pwd
                except:
                    continue
        return finalRet
