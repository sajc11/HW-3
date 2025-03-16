import base64
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256
import imexceptions


class EncryptedBlob:

    # the constructor
    def __init__(self, plaintext=None, confkey=None, authkey=None): 
        self.plaintext = plaintext
        self.ivBase64 = None
        self.ciphertextBase64 = None
        self.macBase64 = None

        # Only encrypt if plaintext and both keys are provided.
        if plaintext is not None and confkey is not None and authkey is not None:
            self.ivBase64, self.ciphertextBase64, self.macBase64 = self.encryptThenMAC(confkey, authkey, plaintext)


    # Encrypts the plaintext using AES-256 in CBC mode with PKCS#7 padding,
    # and generates a SHA256-based HMAC for authenticity using authkey.
    def encryptThenMAC(self, confkey, authkey, plaintext):
        # If the keys are provided as strings, hash them to get 32-byte keys.
        if isinstance(confkey, str):
            confkey = SHA256.new(data=confkey.encode('utf-8')).digest()
        if isinstance(authkey, str):
            authkey = SHA256.new(data=authkey.encode('utf-8')).digest()

        # Pad the plaintext so that its length is a multiple of the AES block size (16 bytes)
        plaintextPadded = pad(bytes(plaintext, 'utf-8'), 16)
        
        # Generate a random 16-byte IV for AES-CBC mode
        iv = get_random_bytes(16)
        
        # Encrypt the padded plaintext using AES-256 in CBC mode
        cipher = AES.new(confkey, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(plaintextPadded)
        
        # Compute an HMAC (SHA-256) over the ciphertext using authkey for integrity/authenticity
        hmac_obj = HMAC.new(authkey, digestmod=SHA256)
        hmac_obj.update(ciphertext)
        mac = hmac_obj.digest()

        # DON'T CHANGE THE BELOW.
        # What we're doing here is converting the iv, ciphertext,
        # and mac (which are all in bytes) to base64 encoding, so that it 
        # can be part of the JSON EncryptedIM object
        ivBase64 = base64.b64encode(iv).decode("utf-8") 
        ciphertextBase64 = base64.b64encode(ciphertext).decode("utf-8") 
        macBase64 = base64.b64encode(mac).decode("utf-8") 
        return ivBase64, ciphertextBase64, macBase64


    # Decrypts the provided ciphertext (after decoding it from base64) and verifies its integrity.
    # If the HMAC verification fails, a FailedAuthenticationError is raised.
    # If decryption or unpadding fails, a FailedDecryptionError is raised.
    def decryptAndVerify(self, confkey, authkey, ivBase64, ciphertextBase64, macBase64):
        # If the keys are provided as strings, hash them to get 32-byte keys.
        if isinstance(confkey, str):
            confkey = SHA256.new(data=confkey.encode('utf-8')).digest()
        if isinstance(authkey, str):
            authkey = SHA256.new(data=authkey.encode('utf-8')).digest()

        iv = base64.b64decode(ivBase64)
        ciphertext = base64.b64decode(ciphertextBase64)
        mac = base64.b64decode(macBase64)
        
        # Verify the HMAC over the ciphertext using authkey.
        hmac_obj = HMAC.new(authkey, digestmod=SHA256)
        hmac_obj.update(ciphertext)
        try:
            hmac_obj.verify(mac)
        except ValueError:
            # If HMAC verification fails, raise a FailedAuthenticationError exception.
            raise imexceptions.FailedAuthenticationError("MAC verification failed")
        
        # If HMAC is verified, proceed to decrypt the ciphertext.
        try:
            cipher = AES.new(confkey, AES.MODE_CBC, iv)
            padded_plaintext = cipher.decrypt(ciphertext)
            # Remove the PKCS#7 padding to recover the original plaintext.
            plaintext_bytes = unpad(padded_plaintext, 16)
            self.plaintext = plaintext_bytes.decode('utf-8')
        except Exception as e:
            # If decryption or unpadding fails, raise a FailedDecryptionError exception.
            raise imexceptions.FailedDecryptionError("Decryption failed: " + str(e))
        
        return self.plaintext
