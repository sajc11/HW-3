from typing import Counter
from encryptedblob import EncryptedBlob


# this test generates a bunch of encrypted blobs and ensures that
# it doesn't see the same IV twice
def test_uniqueIVs():
    seen_ivs = {}
    for i in range(25000):
        e = EncryptedBlob(plaintext="hello")
        iv64,ciphertext64,mac64 = e.encryptThenMAC("foo","bar","wuzzup")
        assert iv64 not in seen_ivs
        seen_ivs[iv64] = True

