lua-codec工具包
=======================================================
鉴于网上很难找全相应的Lua工具，或者难用的要死，因此创建本项目；
<br/>
基于openssl，实现常用的加密、摘要算法的Lua工具包，如hmac, md5, aes, rsa等，具体功能参见示例代码；

编译说明
-------------------------------------------------------
我是基于LuaJIT-2.0.3和openssl 1.0.0编译的，可以根据你的环境改codec.c的include以及Makefile；

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

### HMAC-SHA1编码
	local codec = require('codec')
	local src, key = '123456', '112233'
	local dst = codec.hmac_sha1_encode(src)
	print(dst)
	assert('06285a0e4a99a56f7f9d1e239acad4de7c79ebe9' == dst)

### AES-ECB-PKCS5Padding加解密
	local codec = require('codec')
	local src, key = '123456', '0123456789abcdef'
	local bs = codec.aes_encrypt(src, key)
	local dst = codec.base64_encode(bs)
	print(dst)
	
	local dbs = codec.base64_decode(dst)
	local dsrc = codec.aes_decrypt(dbs, key)
	print(dsrc)

	assert(dsrc == src)

### SHA1WithRSA私钥签名及公钥验签
	local codec = require('codec')
	local src = '123456'
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
	local bs = codec.rsa_private_sign(src, privpem)
	local sign = codec.base64_encode(bs)
	print(sign)
	
	local dbs = codec.base64_decode(sign)
	local pubpem = [[-----BEGIN PUBLIC KEY-----
	MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCsxjKD2lnmkmELoo5QphM/VdRE
	JKym26R0T+19JDa3MVZFDbwgUGT8XM8bElrKgxexhTVRt07btyIejdbiPx7sCbWc
	VP8peZI+QZEVVzaE2Ci5n0lP9v9GUSl0QfZU94uIwl++BVq0VFvbHax/R/q4oTRD
	1u73ASM27QW42+cJFwIDAQAB
	-----END PUBLIC KEY-----]]
	local typ = 2
	local ok = codec.rsa_public_verify(src, dbs, pubpem, typ)
	assert(ok)

rsa_public_verify最后一个参数为公钥串类型，1：PEM  2：PKCS8
就是“-----BEGIN RSA PUBLIC KEY-----”和“-----BEGIN PUBLIC KEY-----”的区别，啦啦啦
	
### RSA公钥加密及私钥解密
	local codec = require('codec')
	local src = '123456'
	local pubpem = [[-----BEGIN PUBLIC KEY-----
	MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCsxjKD2lnmkmELoo5QphM/VdRE
	JKym26R0T+19JDa3MVZFDbwgUGT8XM8bElrKgxexhTVRt07btyIejdbiPx7sCbWc
	VP8peZI+QZEVVzaE2Ci5n0lP9v9GUSl0QfZU94uIwl++BVq0VFvbHax/R/q4oTRD
	1u73ASM27QW42+cJFwIDAQAB
	-----END PUBLIC KEY-----]]
	local typ = 2
	local bs = codec.rsa_public_encrypt(src, pubpem, typ)
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

rsa_public_encrypt最后一个参数为公钥串类型，1：PEM  2：PKCS8
就是“-----BEGIN RSA PUBLIC KEY-----”和“-----BEGIN PUBLIC KEY-----”的区别，再啦啦啦
