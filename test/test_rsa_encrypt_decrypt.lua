local codec = require('codec')
local src = '123456'
local pubpem = [[-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCsxjKD2lnmkmELoo5QphM/VdRE
JKym26R0T+19JDa3MVZFDbwgUGT8XM8bElrKgxexhTVRt07btyIejdbiPx7sCbWc
VP8peZI+QZEVVzaE2Ci5n0lP9v9GUSl0QfZU94uIwl++BVq0VFvbHax/R/q4oTRD
1u73ASM27QW42+cJFwIDAQAB
-----END PUBLIC KEY-----]]
local bs = codec.rsa_public_encrypt(src, pubpem, 2)
local dst = codec.base64_encode(bs)
print(dst)

local privpem = [[-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCsxjKD2lnmkmELoo5QphM/VdREJKym26R0T+19JDa3MVZFDbwg
UGT8XM8bElrKgxexhTVRt07btyIejdbiPx7sCbWcVP8peZI+QZEVVzaE2Ci5n0lP
9v9GUSl0QfZU94uIwl++BVq0VFvbHax/R/q4oTRD1u73ASM27QW42+cJFwIDAQAB
AoGALHoNMQI52HBgSSV8q2hFVi2bKjuisoWibUrSIT/8UeaChd5GSq9Hf+vIaPit
pKpgpBNdqX6d71PSlbj/01hadg5IxrGWQZWzT/3IzuhTxAu4TkztUJelGRcM6ykZ
5AxijiIxTLWSY/ygtEaM2QShhl8dCReNT+oIDGf/iMSTVykCQQDl07WZR9ATReVc
vM7/v9iiz/g1Tj9/8AOuyYOZ5kp5a8IAr48dXixzuTZY66RwPj/J5vrzLuHc7Uc0
RAi4hgmTAkEAwHMxP0KVOzDH49SsiUjfOycqrBl68QCXUWQj2mi7Bb1pLryoYDFv
FTuk6pxKyfr5O8M2s8thTz6f3EO7hFqk7QJAdX8Ly2ZkYUYNoaDBbwzEk1AhhBcR
7bVmHJjXV/ndP0Aw+arHTutTbIJW35TxB5U7hVw6FdN1Ez6XdYgGsVeNUwJAEjlW
SoVFmGtQInT7Oaza5sEYu19WUwgZTC3Nb1tHio2bLj/TOfi0ajBRt53BP0sy2sPr
pC74MgbeIH+RfEERKQJBAIpPkQztkbpZwD9gDiK86U+HHYZrhglxgfDIXYwTH3z/
KCrfyNxiH2im9ZhwuhLs7LDD7wDPHUC5BItx2tYN10s=
-----END RSA PRIVATE KEY-----]]
local dbs = codec.base64_decode(dst)
local dsrc = codec.rsa_private_decrypt(dbs, privpem)
print(dsrc)

assert(dsrc == src)

