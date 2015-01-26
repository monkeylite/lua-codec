local codec = require('codec')
local src = '123456'
local dst = codec.md5_encode(src)
print(dst)
assert('e10adc3949ba59abbe56e057f20f883e' == dst)
