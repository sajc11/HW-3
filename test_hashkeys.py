import client

def test_hashKeys():
    confkeyHash,authkeyHash = client.hashKeys("foo","bar")
    assert confkeyHash.hex() == "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
    assert authkeyHash.hex() == "fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9"

