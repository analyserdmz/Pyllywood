import base64, hashlib
from colorama import init
from termcolor import colored

init()

configJson = {
    "bufLen" : 1024,
    "clUagent" : "RTSP Client"
}

def genDESCRIBE(url, seq, userAgent, authSeq):
    msgRet = "DESCRIBE {} RTSP/1.0\r\n".format(url)
    msgRet += "CSeq: {}\r\n".format(str(seq))
    if authSeq != "":
        msgRet += "Authorization: {}\r\n".format(authSeq)
    msgRet += "User-Agent: {}\r\n".format(userAgent)
    msgRet += "Accept: application/sdp\r\n\r\n"
    return msgRet.encode()

def generateAuthString(username,password,realm,method,uri,nonce):
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
    return mapRetInf.encode()

def authBuilder(authMethod, tempRecv, username, password):
    if authMethod == "basic":
        authSeq = base64.b64encode("{}:{}".format(username, password).encode()).decode()
        authSeq = "Basic {}".format(authSeq)
        return authSeq
    else: # digest
        start = tempRecv.find("realm")
        begin = tempRecv.find("\"", start)
        end = tempRecv.find("\"", begin + 1)
        realm = tempRecv[begin+1:end]
        start = tempRecv.find("nonce")
        begin = tempRecv.find("\"", start)
        end = tempRecv.find("\"", begin + 1)
        nonce = tempRecv[begin+1:end]
        authSeq = generateAuthString(username,password,realm,"DESCRIBE","/sdekfjvhejkhrv",nonce)
        # print(authSeq)
        return authSeq
