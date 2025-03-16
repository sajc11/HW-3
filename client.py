#!/usr/bin/env python3
# client.py:

import socket
import json
import argparse
import logging
import select
import sys
import time
import datetime
import struct
from message import UnencryptedIMMessage

def parseArgs():
    """
    parse the command-line arguments
    """
    parser = argparse.ArgumentParser()
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

def main():
    args = parseArgs()

    # set up the logger
    log = logging.getLogger("myLogger")
    logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s')
    level = logging.getLevelName(args.loglevel)
    
    log.setLevel(level)
    log.info(f"running with {args}")
    
    log.debug(f"Attempting to connect to server {args.server} on port {args.port}")

    try:
        s = socket.create_connection((args.server,args.port))
        log.info("connected to server")
    except:
        log.error("cannot connect")
        exit(1)

    readSet = [s] + [sys.stdin]

    while True:
        try:
            readable, _, exceptional = select.select(readSet, [], readSet)
            
            for source in readable:
                if source == sys.stdin:
                    # Handle user input
                    line = sys.stdin.readline()
                    if not line:  # EOF (Ctrl+D)
                        log.debug("EOF detected, exiting...")
                        return

                    # Check message length before sending
                    if len(line.strip()) > 4096:  # 4KB limit
                        log.error("Message too long. Max size: 4KB")
                        continue
                        
                    # Create and send message
                    if line.strip():  # Only send non-empty messages
                        msg = UnencryptedIMMessage(args.nickname, line.strip())
                        try:
                            packedSize, jsonData = msg.serialize()
                            s.sendall(packedSize + jsonData)
                            log.debug(f"Sent message: {line.strip()}")
                        except (BrokenPipeError, ConnectionResetError):
                            log.error("Lost connection to server. Exiting...")
                            return
                        except Exception as e:
                            log.error(f"Error sending message: {e}")
                            return
                            
                else:  # source == s (socket)
                    try:
                        # Get message length
                        packedLen = s.recv(4, socket.MSG_WAITALL)
                        if not packedLen:
                            log.error("Server has shut down. Exiting...")
                            return
                            
                        # Get message length and verify it's reasonable
                        msgLen = struct.unpack("!L", packedLen)[0]
                        if msgLen > 4096:  # 4KB limit
                            log.error(f"Message too large ({msgLen} bytes)")
                            continue
                        
                        # Get message
                        jsonData = s.recv(msgLen, socket.MSG_WAITALL)
                        if not jsonData:
                            log.error("Server closed connection during message receive")
                            return
                        
                        # Validate JSON before parsing
                        try:
                            json.loads(jsonData)
                        except json.JSONDecodeError as e:
                            log.debug(f"Received invalid JSON: {e}")
                            continue
                            
                        # Parse and print message
                        try:
                            msg = UnencryptedIMMessage()
                            msg.parseJSON(jsonData)
                            print(msg)  # Print exactly as required
                        except Exception as e:
                            log.debug(f"Error parsing message: {e}")
                            continue
                        
                    except (ConnectionResetError, BrokenPipeError):
                        log.error("Lost connection to server")
                        return
                    except Exception as e:
                        log.error(f"Error receiving message: {e}")
                        return
            
            # Handle exceptional conditions
            if exceptional:
                log.error("Socket exception occurred")
                return
                
        except KeyboardInterrupt:
            log.info("Interrupted by user")
            break
        except Exception as e:
            log.error(f"Unexpected error: {e}")
            break

    s.close()
    log.debug("Connection closed")

if __name__ == "__main__":
    exit(main())