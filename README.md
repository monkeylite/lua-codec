lua-codec工具包
=======================================================
鉴于网上很难找全相应的Lua工具，或者难用的要死，因此创建本项目；
基于openssl，实现常用的加密、摘要算法的Lua工具包，如md5, aes, rsa等，具体功能参见示例代码；

编译说明
-------------------------------------------------------
我（行者@coding.net）是基于LuaJIT-2.0.3和openssl 1.0.0编译的，可以根据你的环境改codec.c的include以及Makefile；

	cd src/
	make
	mv codec.so $YOUR_LUA_PACKAGE_PATH（如：/usr/local/lib/lua/5.1）
	

Lua代码示例
-------------------------------------------------------

### BASE64编解码

		local codec = require('codec')
		local src = '123456'
		local dst = codec.base64_encode(src)
		print(dst)
		local dsrc = codec.base64_decode(dst)
		print(dsrc)
		assert(dsrc == src)

### MD5编码

		local codec = require('codec')
		local src = '123456'
		local dst = codec.md5_encode(src)
		print(dst)
		assert('e10adc3949ba59abbe56e057f20f883e' == dst)
