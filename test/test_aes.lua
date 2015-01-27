local codec = require('codec')
local src, key = '123456', '01234567890abcdef'
local bs = codec.aes_encrypt(src, key)
local dst = codec.base64_encode(bs)
print(dst)

local dbs = codec.base64_decode(dst)
local dsrc = codec.aes_decrypt(dbs, key)
print(dsrc)

assert(dsrc == src)
