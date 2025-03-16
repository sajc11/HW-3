import socket
import json
import argparse
import logging
import select
import struct



def parseArgs():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', '-p', 
        dest="port", 
        type=int, 
        default='9999',
        help='port number to listen on')
    parser.add_argument('--loglevel', '-l', 
        dest="loglevel",
        choices=['DEBUG','INFO','WARN','ERROR', 'CRITICAL'], 
        default='INFO',
        help='log level')
    args = parser.parse_args()
    return args


def main():
    args = parseArgs()      # parse the command-line arguments

    # set up logging
    log = logging.getLogger("myLogger")
    logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s')
    level = logging.getLevelName(args.loglevel)
    log.setLevel(level)
    log.info(f"running with {args}")
    
    log.debug("waiting for new clients...")
    serverSock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    serverSock.bind(("",args.port))
    serverSock.listen()

    clientList = []

    while True:
        readSet = clientList + [serverSock]
        rl, _, _ = select.select(readSet, [], [])

        if serverSock in rl:
            clientSock,address = serverSock.accept()
            log.info(f"client connected from {address}")
            clientList += [clientSock]

        for client in [x for x in rl if x != serverSock]:
            log.debug(f"action from client {client}")
            data = client.recv(1024)
            
            if len(data) > 0:
                # send to all other clients
                for otherClient in [x for x in clientList if x != client]:
                    otherClient.send(data)
            else:
                log.info("client disconnected")
                client.close()
                clientList.remove(client)
                            
    

if __name__ == "__main__":
    exit(main())

