import socket

def describe(url, sequence):
    msg = "DESCRIBE {} RTSP/1.0\r\n".format(url)
    msg += "CSeq: {}\r\n".format(sequence)
    msg += "User-Agent: LibVLC/2.1.4 (LIVE555 Streaming Media v2014.01.21)"
    msg += "Accept: application/sdp"
    msg += "\r\n\r\n"
    return msg.encode()

def decide(target, port, url=None):
    try:
        authMethod = None # Starting with None cause we don't know yet
        sequence = 0 # Starting request sequence (needed in each request)
        recBuffer = ""

        if url == None:
            descURL = "rtsp://{}:{}/asdfRandomPathHere".format(target, port) # Avoiding 200 responses
        else:
            descURL = url

        while len(recBuffer) == 0: # Some devices respond with zero-length response (!)
            if sequence > 100:
                break # Break if we get 0-length responses x100 - assume it's a route-first device
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10) # Give socket 20 seconds timeout
            sock.connect((str(target), port)) # Connect to the target
            sock.send(describe(descURL, sequence)) # Send the DESCRIBE request
            recBuffer = sock.recv(1024).decode() # Receive the response
            sequence += 1

        for auth in recBuffer.split("\n"): # For each line in response
            if "WWW-Authenticate:" in auth: # If there is WWW-Authenticate in it
                authMethod = auth.split()[1].strip() # Get the Auth Method
    except:
        return

    return authMethod