local codec = require('codec')

local src = '123456'
local dst = codec.md5_encode(src)

print(dst)
