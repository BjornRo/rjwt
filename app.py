import rjwt
from datetime import timedelta
from base64 import b64decode
import time

priv = """
-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDAG95L6L1Jl4NyeQ73u
gcKJPKYL5pCugtxoutMAATxlWYu6JWjTpltcHjswmBjJ7WWhZANiAASyHJXZTAVV
PTRghJGbsqSRjlYPzPS2vADxAZ/YrcyWDR5C1fJmCRgK2FER03VFoo/uw4s9652b
PPouCmEVGGBkOP9uq5F1k2oSfP21SDfZCbLVvIC0JAMF3JHCefUC+CQ=
-----END PRIVATE KEY-----

"""

pub = """
-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEshyV2UwFVT00YISRm7KkkY5WD8z0trwA
8QGf2K3Mlg0eQtXyZgkYCthREdN1RaKP7sOLPeudmzz6LgphFRhgZDj/bquRdZNq
Enz9tUg32Qmy1byAtCQDBdyRwnn1Avgk
-----END PUBLIC KEY-----
"""

key = rjwt.ECDSA(priv.encode(), pub.encode(), rjwt.HashAlgorithms.ES384)
tok: str = key.encode(timedelta(seconds=1), {"molo":[{"2":4},2,3,4]})

import timeit
import jwt

jwt.decode(jwt.encode({"iat":int(time.time()), "exp": int(time.time())+10}, key=priv, algorithm="ES384"), key=pub, algorithms=["ES384"])


print(timeit.timeit(lambda: key.decode(key.encode(timedelta(seconds=1))), number=1000))
print(timeit.timeit(lambda: jwt.decode(jwt.encode({"iat":int(time.time()), "exp": int(time.time())+10}, key=priv, algorithm="ES384"), key=pub, algorithms=["ES384"]), number=1000))


# key = rjwt.HMAC(b"s", rjwt.HashAlgorithms.SHA384)
# tok: str = key.sign(timedelta(seconds=-10), {"molo":[{"2":4},2,3,4]})
# print(tok)
# tok = tok[:-2] + "0x.3ööö2"
# print(key.verify(tok))

# print(key.sign(timedelta(seconds=10)))
# print(key.sign(timedelta(seconds=10), {}))
# print(key.sign(timedelta(seconds=10), {"molo":123}))
# print(b64decode(key.sign(timedelta(seconds=10), {"molo":[{"2":4},2,3,4]}).split(".")[1]+"=="))
# print(b64decode(key.sign(timedelta(seconds=10), {}).split(".")[1]+"=="))