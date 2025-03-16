# samples.py:

import struct
from message import UnencryptedIMMessage

def main():
    msg = UnencryptedIMMessage("msherr", "cosc4705 is really fun!")

    print( f"Here's the message: {msg}" )

    (packedSize,jsonData) = msg.serialize()

    print( "The message in JSON format is:\n\t", jsonData.decode('UTF-8') )

    print( f"The length of the JSON message in packed (network-byte order) is {packedSize}" )
    print( "But golly, that's difficult to parse.  Let's convert that back to an int." )

    unpackedSize = struct.unpack("!L",packedSize)[0]
    print( f"The unpacked size (i.e., length of the JSON) is {unpackedSize}." )
    

if __name__ == "__main__":
    exit(main())

