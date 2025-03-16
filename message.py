"""
message.py:

An implementation of an unencrypted IM message.

Do not modify any functions in this file.  Depending upon your design,
you *may* want to add a deserialize method.
"""

import time
import json
import datetime
import struct


class UnencryptedIMMessage:

    # the constructor
    def __init__(self, nickname=None, msg=None):
        self.nick = nickname
        self.msg = msg
        self.timestamp = time.time()
    

    # define how this class is printed as a string
    def __repr__(self):
        dt = datetime.datetime.fromtimestamp(self.timestamp)
        humanReadableDate = dt.strftime("%m/%d/%Y %H:%M:%S")
        return f'[{humanReadableDate}] {self.nick} --> {self.msg}'


    # outputs the message in JSON format
    def toJSON(self):
        structuredMessage = {
            "nick": self.nick,
            "message": self.msg,
            "date": self.timestamp,
        }
        return bytes(json.dumps(structuredMessage, sort_keys=True, indent=4),'utf-8')


    # given some json data, parses it and populates the fields
    def parseJSON(self, jsonData):
        try:
            structuredMessage = json.loads(jsonData)
            # check for required fields
            if "message" not in structuredMessage or "nick" not in structuredMessage or "date" not in structuredMessage:
                raise json.JSONDecodeError
            self.nick = structuredMessage["nick"]
            self.msg = structuredMessage["message"].strip()
            self.timestamp = structuredMessage["date"]
        except Exception as err:
            raise err


    # serializes the UnencryptedIMMessage into two parts:
    # 
    # 1. a packed (in network-byte order) length of the JSON object.  This
    #    packed length will always be a 4-byte unsigned long.  It needs
    #    to be unpacked using struct.unpack to convert it back to an int.
    # 
    # 2. the message in JSON format
    def serialize(self):
        jsonData = self.toJSON()
        packedSize = struct.pack('!L', len(jsonData))
        return (packedSize,jsonData)
    
