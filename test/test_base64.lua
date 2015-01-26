local codec = require('codec')
local src = '123456'
local dst = codec.base64_encode(src)
print(dst)
local dsrc = codec.base64_decode(dst)
print(dsrc)
assert(dsrc == src)
