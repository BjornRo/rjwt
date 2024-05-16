import rjwt
from datetime import timedelta
from base64 import b64decode
key = rjwt.HMAC(b"s", rjwt.HashAlgorithms.SHA384)
tok: str = key.sign(timedelta(seconds=-10), {"molo":[{"2":4},2,3,4]})
print(tok)
tok = tok[:-2] + "0x.3ööö2"
print(key.verify(tok))

# print(key.sign(timedelta(seconds=10)))
# print(key.sign(timedelta(seconds=10), {}))
# print(key.sign(timedelta(seconds=10), {"molo":123}))
# print(b64decode(key.sign(timedelta(seconds=10), {"molo":[{"2":4},2,3,4]}).split(".")[1]+"=="))
# print(b64decode(key.sign(timedelta(seconds=10), {}).split(".")[1]+"=="))