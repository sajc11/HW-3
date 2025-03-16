"""
An implementation of an unencrypted IM message.

Do not modify any functions in this file.  Depending upon your design,
you *may* want to add a deserialize method.
"""

import time
import json
import datetime
import struct
from encryptedblob import EncryptedBlob


class EncryptedIMMessage:

    # the constructor.
    def __init__(self, nickname=None, plaintext=None):
        self.nick = nickname
        self.plaintext = plaintext
        self.timestamp = time.time()
    

    # define how this class is printed as a string
    def __repr__(self):
        dt = datetime.datetime.fromtimestamp(self.timestamp)
        humanReadableDate = dt.strftime("%m/%d/%Y %H:%M:%S")
        return f'[{humanReadableDate}] {self.nick} --> {self.plaintext}'


    def toJSON(self, confkey, authkey):

        encNickBlob = EncryptedBlob(self.nick,confkey,authkey)
        encMsgBlob  = EncryptedBlob(self.plaintext,confkey,authkey)
        
        """ outputs the message in JSON format"""
        structuredMessage = {
            "nick": {
                "iv" : encNickBlob.ivBase64,
                "ciphertext" : encNickBlob.ciphertextBase64,
                "mac" : encNickBlob.macBase64
            },                
            "message": {
                "iv" : encMsgBlob.ivBase64,
                "ciphertext" : encMsgBlob.ciphertextBase64,
                "mac" : encMsgBlob.macBase64
            },        
            "date": self.timestamp,
        }
        return bytes(json.dumps(structuredMessage, sort_keys=True, indent=4),'utf-8')


    # given some json data, parses it and populates the fields
    def parseJSON(self, jsonData, confkey, authkey):
        try:
            structuredMessage = json.loads(jsonData)
            # check for required fields
            if "message" not in structuredMessage or "nick" not in structuredMessage or "date" not in structuredMessage:
                raise json.JSONDecodeError
     
            self.timestamp = structuredMessage["date"]
            
            # parse nickname and message
            nick = structuredMessage["nick"]
            message = structuredMessage["message"]

            encNickBlob = EncryptedBlob()
            encNickBlob.ivBase64 = nick["iv"]
            encNickBlob.ciphertextBase64 = nick["ciphertext"]
            encNickBlob.macBase64 = nick["mac"]

            # decrypt the nickname
            self.nick = encNickBlob.decryptAndVerify(
                confkey,
                authkey,
                encNickBlob.ivBase64,
                encNickBlob.ciphertextBase64,
                encNickBlob.macBase64)
            
            encMessageBlob = EncryptedBlob()
            encMessageBlob.ivBase64 = message["iv"]
            encMessageBlob.ciphertextBase64 = message["ciphertext"]
            encMessageBlob.macBase64 = message["mac"]

            # decrypt the message
            self.plaintext = encMessageBlob.decryptAndVerify(
                confkey,
                authkey,
                encMessageBlob.ivBase64,
                encMessageBlob.ciphertextBase64,
                encMessageBlob.macBase64)
            
        except Exception as err:
            raise err


    # serializes the EncryptedIMMessage into two parts:
    # 
    # 1. a packed (in network-byte order) length of the JSON object. This
    #    packed length will always be a 4-byte unsigned long. It needs
    #    to be unpacked using struct.unpack to convert it back to an int.
    # 
    # 2. the message in JSON format
    #

    def serialize(self, confkey, authkey):
        jsonData = self.toJSON(confkey, authkey)
        packedSize = struct.pack('!L', len(jsonData))
        return (packedSize, jsonData)
    
    # New class method to deserialize a message from JSON data - more streamlined than parseJSON
    @classmethod
    def deserialize(cls, jsonData, confkey, authkey):
        msg = cls()
        msg.parseJSON(jsonData, confkey, authkey)
        return msg