#!/usr/bin/env python3
# server.py:

import socket
import json
import argparse
import logging
import select
import struct
import time
import sys
import signal

# could add signal to track cmd+c "violent exits"

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
    serverSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serverSock.bind(("", args.port))
    serverSock.listen()

    log.debug(f"Server is running on port {args.port} and listening for connections...")
    
    # Keep track of all sockets
    readSet = [serverSock]
    
    def remove_client(sock):
        """Helper function to properly clean up client sockets"""
        try:
            if sock in readSet:
                readSet.remove(sock)
            sock.close()
            log.debug("Client disconnected and cleaned up")
        except:
            pass

    def handle_shutdown(signal, frame):
        """Handle SIGINT or SIGTERM to gracefully shut down the server"""
        log.info("Caught shutdown signal. Cleaning up and exiting...")
        for sock in readSet[:]:
            remove_client(sock)
        exit(0)

    # Register signal handlers
    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)

    # Main loop to handle incoming connections and messages
    while True:
        try:
            # Use select to monitor sockets
            readable, _, exceptional = select.select(readSet, [], readSet)
            
            for sock in readable:
                if sock == serverSock:
                    # Handle new connection
                    clientSock, address = serverSock.accept()
                    readSet.append(clientSock)
                    log.debug(f"New client connected from {address}")
                else:
                    try:
                        # Get message length
                        packedLen = sock.recv(4, socket.MSG_WAITALL)
                        if not packedLen:
                            log.info(f"Client {sock.getpeername()} disconnected gracefully.")
                            remove_client(sock)
                            continue

                        # Get message length and validate
                        msgLen = struct.unpack("!L", packedLen)[0]
                        if msgLen > 4096:  # 4KB limit, matching client
                            log.debug(f"Oversized message ({msgLen} bytes) rejected")
                            remove_client(sock)
                            continue

                        # Get message content
                        jsonData = sock.recv(msgLen, socket.MSG_WAITALL)
                        if not jsonData:
                            log.info(f"Client {sock.getpeername()} disconnected gracefully.")
                            remove_client(sock)
                            continue

                        # Validate JSON before forwarding
                        try:
                            json.loads(jsonData)
                        except json.JSONDecodeError:
                            log.debug("Invalid JSON received, skipping")
                            continue

                        # Forward message to other clients
                        disconnected = []
                        for client in readSet:
                            if client != serverSock and client != sock:
                                try:
                                    client.sendall(packedLen + jsonData)
                                except (BrokenPipeError, ConnectionResetError):
                                    disconnected.append(client)
                                except Exception as e:
                                    log.error(f"Unexpected error sending to client: {e}")
                                    disconnected.append(client)

                        # Clean up disconnected clients
                        for client in disconnected:
                            remove_client(client)

                    # Handle abrupt disconnections
                    except (ConnectionResetError, BrokenPipeError):
                        log.info(f"Client {sock.getpeername()} disconnected unexpectedly.")
                        remove_client(sock)
                    except Exception as e:
                        log.error(f"Unexpected error handling client: {e}")
                        remove_client(sock)

            # Handle exceptional conditions
            for sock in exceptional:
                log.debug("Handling exceptional condition")
                remove_client(sock)

        except KeyboardInterrupt:
            log.info("Server shutting down...")
            break
        except Exception as e:
            log.error(f"Server error: {e}")
            continue

    # Clean up all connections
    for sock in readSet[:]:  # changed from: sock in readSet:
        remove_client(sock)
    log.debug("Server shutdown complete")

if __name__ == "__main__":
    exit(main())