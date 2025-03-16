import socket
import json
import argparse
import logging
import select
import sys
import time
import datetime
import struct
from message import EncryptedIMMessage
from Crypto.Hash import SHA256


def parseArgs():
    """
    parse the command-line arguments
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('--confkey', '-c', 
        dest="confkey", 
        required=True,
        help='confidentiality key')
    parser.add_argument('--authkey', '-a', 
        dest="authkey", 
        required=True,
        help='authenticity key')       
    parser.add_argument('--port', '-p', 
        dest="port", 
        type=int, 
        default='9999',
        help='port number to connect to')
    parser.add_argument('--server', '-s', 
        dest="server", 
        required=True,
        help='server to connect to')       
    parser.add_argument('--nickname', '-n', 
        dest="nickname", 
        required=True,
        help='nickname')                
    parser.add_argument('--loglevel', '-l', 
        dest="loglevel",
        choices=['DEBUG','INFO','WARN','ERROR', 'CRITICAL'], 
        default='INFO',
        help='log level')
    args = parser.parse_args()
    return args




# Updated: Return a tuple of two SHA-256 binary digests.
# The first digest is computed from the confidentiality key (confkey)
# and the second digest is computed from the authenticity key (authkey).
# Both keys are first converted to ASCII-encoded bytes, and then hashed.
# Note: Do not use hexdigest()—return the raw byte digest.
def hashKeys(confkey, authkey):
    # Convert the keys to ASCII-encoded bytes
    confkey_bytes = bytes(confkey, 'ascii')
    authkey_bytes = bytes(authkey, 'ascii')
    
    # Compute the SHA-256 hash for each key and obtain the raw binary digest
    confkeyHash = SHA256.new(data=confkey_bytes).digest()
    authkeyHash = SHA256.new(data=authkey_bytes).digest()
    
    return confkeyHash, authkeyHash



def main():
    args = parseArgs()

    log = logging.getLogger("myLogger")
    logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s')
    level = logging.getLevelName(args.loglevel)
    
    log.setLevel(level)
    log.info(f"running with {args}")

    hashedConfkey,hashedAuthkey = hashKeys(args.confkey, args.authkey)
    
    log.debug(f"connecting to server {args.server}")
    s = socket.create_connection((args.server,args.port))

    readSet = [s] + [sys.stdin]

    dataLenSize = struct.calcsize('!L')

    while True:
        rl, _, _ = select.select(readSet, [], [])

        if s in rl:
            log.debug(f"waiting for {dataLenSize} bytes")
            try:
                packedSize = s.recv(dataLenSize,socket.MSG_WAITALL)
                if len(packedSize) == 0:
                    log.fatal("server disconnected!")
                    exit(1)
                unpackedSize = struct.unpack("!L",packedSize)[0]
                log.debug(f"message is {unpackedSize} bytes")
                data = s.recv(unpackedSize,socket.MSG_WAITALL)
            except Exception as err:
                log.error(f"exception occurred: {err}")
            msg = EncryptedIMMessage()
            try:
                msg.parseJSON(data,hashedConfkey,hashedAuthkey)
            except Exception as err:
                log.warning(f"invalid message received: {err}")
            print(msg)

        if sys.stdin in rl:
            keyboardInput = sys.stdin.readline()
            if len(keyboardInput) == 0:
                exit(0)
            msg = EncryptedIMMessage(
                nickname=args.nickname, 
                plaintext=keyboardInput)
            packedSize, jsonData = msg.serialize(hashedConfkey,hashedAuthkey)
            s.send(packedSize)
            log.debug(f"sending raw JSON: {jsonData}")
            s.send(jsonData)


if __name__ == "__main__":
    exit(main())

