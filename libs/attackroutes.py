import socket, base64, hashlib
from libs import routebuilder

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

def start(target, port, authmethod, username=None, password=None):
    finalRoutes = []

    try:
        # We connect to the target in a loop (some DIGEST AUTH devices terminate the connection if a route is found)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(20) # We allow 3 seconds of timeout
        sock.connect((target, port)) # Double parenthesis required
        sequence = 1 # Starting request sequence (needed in each request)
    except:
        return

    if authmethod == None: # Here we try to find valid routes first (without user/pass combos)
        for route in routebuilder.build(): # Letting username & password intact (invalid)
            try:
                recBuffer = ""

                descURL = "rtsp://{}:{}/{}".format(target, port, route) # Complete DESCRIBE URL

                sock.send(describe(descURL, sequence)) # Sending DESCRIBE request
                recBuffer = sock.recv(1024).decode() # Receive the response
                sequence += 1

                if "RTSP/1.0 401" in recBuffer or "RTSP/1.0 403" in recBuffer:
                    if descURL not in finalRoutes:
                        finalRoutes.append(descURL)
            except:
                continue
    elif authmethod == "Basic":
        try:
            # We connect to the target in a loop (some DIGEST AUTH devices terminate the connection if a route is found)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(20) # We allow 3 seconds of timeout
            sock.connect((target, port)) # Double parenthesis required
            sequence = 1 # Starting request sequence (needed in each request)
        except:
            return

        for route in routebuilder.build(username, password): # Building the route list with user and pass this time
            try:
                recBuffer = ""

                descURL = "rtsp://{}:{}@{}:{}/{}".format(username, password, target, port, route) # Complete DESCRIBE URL for Basic Auth

                sock.send(describe(descURL, sequence, authBuilder(authmethod, "", username, password, descURL)))
                recBuffer = sock.recv(1024).decode() # Receive the response
                sequence += 1
                # print(recBuffer)
                if "RTSP/1.0 200" in recBuffer:
                    if descURL not in finalRoutes:
                        finalRoutes.append(descURL)
            except:
                continue
    else: # Digest
        try:
            # We connect to the target in a loop (some DIGEST AUTH devices terminate the connection if a route is found)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(20) # We allow 3 seconds of timeout
            sock.connect((target, port)) # Double parenthesis required
            sequence = 1 # Starting request sequence (needed in each request)
        except:
            return

        for route in routebuilder.build(username, password): # Building the route list with user and pass this time
            try:
                recBuffer = ""
                digestBuffer = ""

                descURL = "rtsp://{}:{}/{}".format(target, port, route)

                # Get digest response (nonce, realm etc)
                sock.send(describe(descURL, sequence))
                digestBuffer = sock.recv(1024).decode()
                sequence += 1

                sock.send(describe(descURL, sequence, authBuilder(authmethod, digestBuffer, username, password, "/{}".format(route))))
                recBuffer = sock.recv(1024).decode() # Receive the response
                sequence += 1

                if "RTSP/1.0 200" in recBuffer:
                    if "rtsp://{}:{}@{}:{}/{}".format(username, password, target, port, route) not in finalRoutes:
                        finalRoutes.append("rtsp://{}:{}@{}:{}/{}".format(username, password, target, port, route))
            except:
                continue
    return finalRoutes