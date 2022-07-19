import ecdsa
import random
import hashlib
#python中有对应的椭圆曲线签名的函数库，可直接生成签名所需密钥
gen=ecdsa.NIST256p.generator
rank=gen.order()
# 1、选择一条椭圆曲线Ep(a,b)，和基点G；
# 2、选择私有密钥k（k<n，n为G的阶），利用基点G计算公开密钥K=kG；
# 3、产生一个随机整数r（r<n），计算点R=rG；
privateKey = random.randrange(1,rank-1)
publicKey = ecdsa.ecdsa.Public_key(gen,gen * privateKey)
private_key = ecdsa.ecdsa.Private_key(publicKey,privateKey)
# 4、将原数据和点R的坐标值x,y作为参数，计算SHA1做为hash，即Hash=SHA1(原数据,x,y)；
# 5、计算s≡r - Hash * k (mod n) 6、r和s做为签名值，如果r和s其中一个为0，
message = "sunzehan's power."
m = int(hashlib.sha1(message.encode("utf8")).hexdigest(),16)
k = random.randrange(1,rank-1)
signature = private_key.sign(m,k)
r = signature.r
s = signature.s