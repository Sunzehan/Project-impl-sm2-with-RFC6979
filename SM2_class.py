# SM2类继承ECC，我们使用了通用ECC模型的思路
# 改变一下相关参数与实现逻辑的简化！
class SM2(ECC):
    # 默认使用SM2推荐曲线参数（安全参数中标明国家密码管理局：SM2椭圆曲线公钥密码算法推荐曲线参数）
    def __init__(self, p=SM2_p, a=SM2_a, b=SM2_b, n=SM2_n, G=(SM2_Gx, SM2_Gy), h=None,
                 ID=None, sk=None, pk=None, genkeypair=True):  
        # genkeypair为布尔型变量表示是否自动生成公私钥对
        if not h:  # 余因子h默认为1
            h = 1
        ECC.__init__(self, p, a, b, n, G, h)

        self.keysize = len(to_byte(n))  # 密钥长度（字节）
        if type(ID) in (int, str):  # 身份ID（数字或字符串）
            self.ID = ID
        else:
            self.ID = ''
        if sk and pk:  # 如果提供的公私钥对通过验证，即使genkeypair=True也不会重新生成
            self.sk = sk  # 私钥（int [1,n-2]）
            self.pk = pk  # 公钥（x, y）
            self.confirm_keypair()  # 验证该公私钥对，不合格则生成
        elif genkeypair:  # 自动生成合格的公私钥对
            self.confirm_keypair()

        # 预先计算用到的常数
        if hasattr(self, 'sk'):  # 签名时
            self.d_1 = get_inverse(1 + self.sk, self.n)

    # 椭圆曲线系统参数验证
    # SM2第1部分 5.2.2
    def para_valid(self):
        # a) 验证q = p是奇素数
        if not prime_judge(self.p):
            self.error = 'p不是素数'  # 记录错误信息
            return False
        # b) 验证a、b、Gx和Gy是区间[0, p−1]中的整数
        if not self.on_Fp(self.a, self.b, *self.G):
            self.error = 'a、b或G坐标值不是域Fp中的元素'
            return False
        # d) 验证(4a^3 + 27b^2) mod p != 0
        if (4 * self.a * self.a * self.a + 27 * self.b * self.b) % self.p == 0:
            self.error = '(4a^3 + 27b^2) mod p = 0'
            return False
        # e) 验证Gy^2 = Gx^3 + aGx + b (mod p)
        if not self.on_curve(self.G):
            self.error = 'G不在椭圆曲线上'
            return False
        # f) 验证n是素数，n > 2^191 且 n > 4p^1/2
        if not prime_judge(self.n) or self.n <= 1 << 191 or self.n <= 4 * self.p ** 0.5:
            self.error = 'n不是素数或n不够大'
            return False
        # g) 验证[n]G = O
        if not self.is_zero(self.Jacb_multiply(self.n, self.G, False)):
            self.error = '[n]G不是无穷远点'
            return False
        # i) 验证抗MOV攻击条件和抗异常曲线攻击条件成立（A.4.2.1）
        B = 27  # MOV阈B
        t = 1
        for i in range(B):
            t = t * self.p % self.n
            if t == 1:
                self.error = '不满足抗MOV攻击条件'
                return False
        # 椭圆曲线的阶N=#E(Fp)计算太复杂，未实现A.4.2.2验证
        # Fp上的绝大多数椭圆曲线确实满足抗异常曲线攻击条件
        return True

    # 计算Z
    # SM2第2部分 5.5
    # ID为数字或字符串，P为公钥（不提供参数时返回自身Z值）
    def get_Z(self, ID=None, P=None):
        save = False
        if not P:  # 不提供参数
            if hasattr(self, 'Z'):  # 再次计算，返回曾计算好的自身Z值
                return self.Z
            else:  # 首次计算自身Z值
                ID = self.ID
                P = self.pk
                save = True
        entlen = get_bit_num(ID)
        ENTL = to_byte(entlen, 2)
        Z = sm3(join_bytes([ENTL, ID, self.a, self.b, *self.G, *P]))
        if save:  # 保存自身Z值
            self.Z = Z
        return Z

    # 数字签名
    # SM2第2部分 6.1
    # 输入：待签名的消息M、随机数k（不填则自动生成）、输出类型（默认bytes）、对M是否hash（默认是）
    # 输出：r, s（int类型）或拼接后的bytes
    def sign(self, M, k=None, outbytes=True, dohash=True):
        if dohash:
            M_ = join_bytes([self.get_Z(), M])
            e = to_int(sm3(M_))
        else:
            e = to_int(to_byte(M))
        while True:
            if not k:
                k = random.randint(1, self.n - 1)
            # x1, y1 = self.multiply(k, self.G)
            x1, y1 = self.Jacb_multiply(k, self.G)
            r = (e + x1) % self.n
            if r == 0 or r + k == self.n:
                k = 0
                continue
            # s = get_inverse(1 + self.sk, self.n) * (k - r * self.sk) % self.n
            s = self.d_1 * (k - r * self.sk) % self.n
            if s == 0:
                k = 0
            else:
                break
        if outbytes:
            return to_byte((r, s), self.keysize)
        else:
            return r, s

    # 数字签名验证
    # SM2第2部分 7.1
    # 输入：收到的消息M′及其数字签名(r′, s′)、签名者的身份标识IDA及公钥PA、对M是否hash（默认是）
    # 输出：True or False
    def verify(self, M, sig, IDA, PA, dohash=True):
        if isinstance(sig, bytes):
            r = to_int(sig[:self.keysize])
            s = to_int(sig[self.keysize:])
        else:
            r, s = sig
        if not 1 <= r <= self.n - 1:
            return False
        if not 1 <= s <= self.n - 1:
            return False
        if dohash:
            M_ = join_bytes([self.get_Z(IDA, PA), M])
            e = to_int(sm3(M_))
        else:
            e = to_int(to_byte(M))
        t = (r + s) % self.n
        if t == 0:
            return False
        sG = self.Jacb_multiply(s, self.G, False)
        tPA = self.Jacb_multiply(t, PA, False)
        x1, y1 = self.Jacb_to_affine(self.Jacb_add(sG, tPA))
        R = (e + x1) % self.n
        if R == r:
            return True
        else:  # 避免Jacobian坐标下的等价点导致判断失败
            x1, y1 = self.add(self.Jacb_to_affine(sG), self.Jacb_to_affine(tPA))
            R = (e + x1) % self.n
            return R == r

    # A 发起协商
    # SM2第3部分 6.1 A1-A3
    # 返回rA、RA
    def agreement_initiate(self):
        return self.gen_keypair()

    # B 响应协商（option=True时计算选项部分）
    # SM2第3部分 6.1 B1-B9
    def agreement_response(self, RA, PA, IDA, option=False, rB=None, RB=None, klen=None):
        # 参数准备
        if not self.on_curve(RA):
            return False, 'RA不在椭圆曲线上'
        x1, y1 = RA
        w = math.ceil(math.ceil(math.log(self.n, 2)) / 2) - 1
        if not hasattr(self, 'sk'):
            self.confirm_keypair()
        h = 1  # SM2推荐曲线的余因子h=1
        ZA = self.get_Z(IDA, PA)
        ZB = self.get_Z()
        # B1-B7
        if not rB:
            rB, RB = self.gen_keypair()
        x2, y2 = RB
        x_2 = (1 << w) + (x2 & (1 << w) - 1)
        tB = (self.sk + x_2 * rB) % self.n
        x_1 = (1 << w) + (x1 & (1 << w) - 1)
        # V = self.multiply(h * tB, self.add(PA, self.multiply(x_1, RA)))
        V = self.Jacb_multiply(h * tB, self.Jacb_add(self.Jacb_multiply(x_1, RA, False), PA))
        if self.is_zero(V):
            return False, 'V是无穷远点'
        xV, yV = V
        if not klen:
            klen = KEY_LEN
        KB = KDF(join_bytes([xV, yV, ZA, ZB]), klen)
        if not option:
            return True, (RB, KB)
        # B8、B10（可选部分）
        tmp = join_bytes([yV, sm3(join_bytes([xV, ZA, ZB, x1, y1, x2, y2]))])
        SB = sm3(join_bytes([2, tmp]))
        S2 = sm3(join_bytes([3, tmp]))
        return True, (RB, KB, SB, S2)

    # A 协商确认
    # SM2第3部分 6.1 A4-A10
    def agreement_confirm(self, rA, RA, RB, PB, IDB, SB=None, option=False, klen=None):
        # 参数准备
        if not self.on_curve(RB):
            return False, 'RB不在椭圆曲线上'
        x1, y1, x2, y2 = *RA, *RB
        w = math.ceil(math.ceil(math.log(self.n, 2)) / 2) - 1
        if not hasattr(self, 'sk'):
            self.confirm_keypair()
        h = 1  # SM2推荐曲线的余因子h=1
        ZA = self.get_Z()
        ZB = self.get_Z(IDB, PB)
        # A4-A8
        x_1 = (1 << w) + (x1 & (1 << w) - 1)
        tA = (self.sk + x_1 * rA) % self.n
        x_2 = (1 << w) + (x2 & (1 << w) - 1)
        # U = self.multiply(h * tA, self.add(PB, self.multiply(x_2, RB)))
        U = self.Jacb_multiply(h * tA, self.Jacb_add(self.Jacb_multiply(x_2, RB, False), PB))
        if self.is_zero(U):
            return False, 'U是无穷远点'
        xU, yU = U
        if not klen:
            klen = KEY_LEN
        KA = KDF(join_bytes([xU, yU, ZA, ZB]), klen)
        if not option or not SB:
            return True, KA
        # A9-A10（可选）
        tmp = join_bytes([yU, sm3(join_bytes([xU, ZA, ZB, x1, y1, x2, y2]))])
        S1 = sm3(join_bytes([2, tmp]))
        if S1 != SB:
            return False, 'S1 != SB'
        SA = sm3(join_bytes([3, tmp]))
        return True, (KA, SA)

    # B 协商确认（可选）
    # SM2第3部分 6.1 B10
    def agreement_confirm2(self, S2, SA):
        if S2 != SA:
            return False, 'S2 != SA'
        return True, ''

    # 加密
    # SM2第4部分 6.1
    # 输入：待加密的消息M（bytes或str类型）、对方的公钥PB、随机数k（不填则自动生成）
    # 输出(True, bytes类型密文)或(False, 错误信息)
    def encrypt(self, M, PB, k=None):
        if self.is_zero(self.multiply(self.h, PB)):  # S
            return False, 'S是无穷远点'
        M = to_byte(M)
        klen = get_bit_num(M)
        while True:
            if not k:
                k = random.randint(1, self.n - 1)
            # x2, y2 = self.multiply(k, PB)
            x2, y2 = self.Jacb_multiply(k, PB)
            t = to_int(KDF(join_bytes([x2, y2]), klen))
            if t == 0:  # 若t为全0比特串则继续循环
                k = 0
            else:
                break
        # C1 = to_byte(self.multiply(k, self.G), self.keysize) # (x1, y1)
        C1 = to_byte(self.Jacb_multiply(k, self.G), self.keysize)  # (x1, y1)
        C2 = to_byte(to_int(M) ^ t, klen >> 3)
        C3 = sm3(join_bytes([x2, M, y2]))
        return True, join_bytes([C1, C2, C3])

    # 解密
    # SM2第4部分 7.1
    # 输入：密文C（bytes类型）
    # 输出(True, bytes类型明文)或(False, 错误信息)
    def decrypt(self, C):
        x1 = to_int(C[:self.keysize])
        y1 = to_int(C[self.keysize:self.keysize << 1])
        C1 = (x1, y1)
        if not self.on_curve(C1):
            return False, 'C1不满足椭圆曲线方程'
        if self.is_zero(self.multiply(self.h, C1)):  # S
            return False, 'S是无穷远点'
        # x2, y2 = self.multiply(self.sk, C1)
        x2, y2 = self.Jacb_multiply(self.sk, C1)
        klen = len(C) - (self.keysize << 1) - HASH_SIZE << 3
        t = to_int(KDF(join_bytes([x2, y2]), klen))
        if t == 0:
            return False, 't为全0比特串'
        C2 = C[self.keysize << 1:-HASH_SIZE]
        M = to_byte(to_int(C2) ^ t, klen >> 3)
        u = sm3(join_bytes([x2, M, y2]))
        C3 = C[-HASH_SIZE:]
        if u != C3:
            return False, 'u != C3'
        return True, M
