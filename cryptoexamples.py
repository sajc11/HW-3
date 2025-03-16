from Crypto.Hash import HMAC, SHA256


def myHMAC( preimage ):
    # let's hardcode a key -- something you should NEVER do
    # not secure for real-world applications
    mykey = b'cosc435_is_the_best'
    h = HMAC.new(mykey, digestmod=SHA256)
    h.update(preimage)
    return h.hexdigest()

def main():
    mymessage = b'hello world!'
    print( myHMAC(mymessage) )

if __name__ == '__main__':
    exit(main())


