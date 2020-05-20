import socket, time

configJson = {
    "bufLen" : 1024,
    "clUagent" : "RTSP Client"
}

def describe_GETAUTH(url,seq,userAgent):
    msgRet = "DESCRIBE {} RTSP/1.0\r\n".format(url)
    msgRet += "CSeq: {}\r\n".format(str(seq))
    msgRet += "User-Agent: {}\r\n".format(userAgent)
    msgRet += "\r\n"
    return msgRet.encode()

def detect_auth(target, port):
    try: # Used to avoid time-out errors that breaks the flow
        seq = 1
        authMethod = None
        # Some non-existent path here, to avoid 200 at /
        targetURL = "rtsp://{}:{}/sdekfjvhejkhrv".format(target, port)
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((str(target), port))
        s.send(describe_GETAUTH(targetURL,seq,configJson["clUagent"]))
        tempRecv = s.recv(configJson["bufLen"]).decode()
        # print(tempRecv)
        for authLine in tempRecv.split("\n"):
            if "WWW-Authenticate:" in authLine:
                authMethod = authLine.split()[1].strip()

        if authMethod == "Basic":
            return "basic"
        elif authMethod == "Digest":
            return "digest"
        else:
            return None
    except:
        return None
