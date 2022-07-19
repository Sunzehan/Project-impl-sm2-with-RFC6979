import random
import time
import math
import numpy as np
from pysmx.SM3 import digest as sm3

# 小素数列表，加快判断素数速度
# 这里选取了1000以内的所有素数用于加快判定。
primes_Array = np.array([2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41,
                         43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109,
                         113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191,
                         193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269,
                         271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353,
                         359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439,
                         443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523,
                         541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617,
                         619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709,
                         719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811,
                         821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907,
                         911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997])


def prime_judge(num):
    # 素数判定,应用prime_Array筛选
    # 排除0,1和负数排除小素数的倍数未分辨出来的大整数用rabin算法判断
    if num < 2:
        return False
    for prime in primes_Array:
        if num % prime == 0:
            return False
    return miller_rabin(num)

def miller_rabin(num):
    s = num - 1
    t = 0
    while s & 1 == 0:
        s >>= 1
        t += 1
    for trials in range(5):
        a = random.randrange(2, num - 1)
        v = pow(a, s, num)
        if v != 1:
            i = 0
            while v != (num - 1):
                if i == t - 1:
                    return False
                else:
                    i = i + 1
                    v = v * v % num
    return True


# 将字节转换为int
def to_int(byte):
    return int.from_bytes(byte, byteorder='big')


# 转换为bytes，第二参数为字节数(可选)
def to_byte(x, size=None):
    if isinstance(x, int):
        if size is None:  # 计算合适的字节数
            size = 0
            tmp = x >> 64
            while tmp:
                size += 8
                tmp >>= 64
            tmp = x >> (size << 3)
            while tmp:
                size += 1
                tmp >>= 8
        elif x >> (size << 3):  # 指定的字节数不够则截取低位
            x &= (1 << (size << 3)) - 1
        return x.to_bytes(size, byteorder='big')
    elif isinstance(x, str):
        x = x.encode()
        if size != None and len(x) > size:  # 超过指定长度
            x = x[:size]  # 截取左侧字符
        return x
    elif isinstance(x, bytes):
        if size != None and len(x) > size:  # 超过指定长度
            x = x[:size]  # 截取左侧字节
        return x
    elif isinstance(x, tuple) and len(x) == 2 and type(x[0]) == type(x[1]) == int:
        # 针对坐标形式(x, y)
        return to_byte(x[0], size) + to_byte(x[1], size)
    return bytes(x)


# 将列表元素转换为bytes并连接
def join_bytes(data_list):
    return b''.join([to_byte(i) for i in data_list])


# 求最大公约数
def gcd(a, b):
    return a if b == 0 else gcd(b, a % b)


# 求乘法逆元过程中的辅助递归函数
def get_(a, b):
    if b == 0:
        return 1, 0
    x1, y1 = get_(b, a % b)
    x, y = y1, x1 - a // b * y1
    return x, y


# 求乘法逆元
def get_inverse(a, p):
    # return pow(a, p-2, p) # 效率较低、n倍点的时候两种计算方法结果会有不同
    if gcd(a, p) == 1:
        x, y = get_(a, p)
        return x % p
    return 1


def get_cpu_time():
    return time.perf_counter()


# 密钥派生函数（从一个共享的秘密比特串中派生出密钥数据）
# SM2第3部分 5.4.3
# Z为bytes类型
# klen表示要获得的密钥数据的比特长度（8的倍数），int类型
# 输出为bytes类型
def KDF(Z, klen):
    ksize = klen >> 3
    K = bytearray()
    for ct in range(1, math.ceil(ksize / HASH_SIZE) + 1):
        K.extend(sm3(Z + to_byte(ct, 4)))
    return K[:ksize]


# 计算比特位数
def get_bit_num(x):
    if isinstance(x, int):
        num = 0
        tmp = x >> 64
        while tmp:
            num += 64
            tmp >>= 64
        tmp = x >> num >> 8
        while tmp:
            num += 8
            tmp >>= 8
        x >>= num
        while x:
            num += 1
            x >>= 1
        return num
    elif isinstance(x, str):
        return len(x.encode()) << 3
    elif isinstance(x, bytes):
        return len(x) << 3
    return 0


# 椭圆曲线密码类（实现一般的EC运算，不局限于SM2）
class ECC:
    def __init__(self, p, a, b, n, G, h=None):
        self.p = p
        self.a = a
        self.b = b
        self.n = n
        self.G = G
        if h:
            self.h = h
        self.O = (-1, -1)  # 定义仿射坐标下无穷远点（零点）

        # 预先计算Jacobian坐标两点相加时用到的常数
        self._2 = get_inverse(2, p)
        self.a_3 = (a + 3) % p

    # 椭圆曲线上两点相加（仿射坐标）
    # SM2第1部分 3.2.3.1
    # 仅提供一个参数时为相同坐标点相加
    def add(self, P1, P2=None):
        x1, y1 = P1
        if P2 is None or P1 == P2:  # 相同坐标点相加
            # 处理无穷远点
            if P1 == self.O:
                return self.O
            # 计算斜率k（k已不具备明确的几何意义）
            k = (3 * x1 * x1 + self.a) * get_inverse(2 * y1, self.p) % self.p
            # 计算目标点坐标
            x3 = (k * k - x1 - x1) % self.p
            y3 = (k * (x1 - x3) - y1) % self.p
        else:
            x2, y2 = P2
            # 处理无穷远点
            if P1 == self.O:
                return P2
            if P2 == self.O:
                return P1
            if x1 == x2:
                return self.O
            # 计算斜率k
            k = (y2 - y1) * get_inverse(x2 - x1, self.p) % self.p
            # 计算目标点坐标
            x3 = (k * k - x1 - x2) % self.p
            y3 = (k * (x1 - x3) - y1) % self.p
        return x3, y3

    # 椭圆曲线上的点乘运算（仿射坐标）
    def multiply(self, k, P):
        # 判断常数k的合理性
        assert type(k) is int and k >= 0, 'factor value error'
        # 处理无穷远点
        if k == 0 or P == self.O:
            return self.O
        if k == 1:
            return P
        elif k == 2:
            return self.add(P)
        elif k == 3:
            return self.add(P, self.add(P))
        elif k & 1 == 0:  # k/2 * P + k/2 * P
            return self.add(self.multiply(k >> 1, P))
        elif k & 1 == 1:  # P + k/2 * P + k/2 * P
            return self.add(P, self.add(self.multiply(k >> 1, P)))

    # 输入P，返回-P
    def minus(self, P):
        Q = list(P)
        Q[1] = -Q[1]
        return tuple(Q)

    # Jacobian加重射影坐标下两点相加
    # SM2第1部分 A.1.2.3.2
    # 输入点包含两项时为仿射坐标，三项为Jacobian加重射影坐标，两点坐标系可不同
    # 两点相同时省略第二个参数
    def Jacb_add(self, P1, P2=None):
        if P2 is None or P1 == P2:  # 相同点相加
            # 处理无穷远点
            if P1 == self.O:
                return self.O

            # 根据参数包含的项数判断坐标系（是仿射坐标则转Jacobian坐标）
            x1, y1, z1 = P1 if len(P1) == 3 else (*P1, 1)

            # t1 = 3 * x1**2 + self.a * pow(z1, 4, self.p)
            # t2 = 4 * x1 * y1**2
            # t3 = 8 * pow(y1, 4, self.p)
            # x3 = (t1**2 - 2 * t2) % self.p
            # y3 = (t1 * (t2 - x3) - t3) % self.p
            # z3 = 2 * y1 * z1 % self.p
            z3 = (y1 * z1 << 1) % self.p
            if z3 == 0:  # 处理无穷远点
                return self.O
            T2 = y1 * y1 % self.p
            T4 = (T2 << 3) % self.p
            T5 = x1 * T4 % self.p
            T6 = z1 * z1 % self.p
            T1 = (x1 + T6) * (x1 - T6) * 3 % self.p
            T1 = (T1 + self.a_3 * T6 * T6) % self.p
            T3 = T1 * T1 % self.p
            T2 = T2 * T4 % self.p
            x3 = (T3 - T5) % self.p
            T4 = T5 + (T5 + self.p >> 1) - T3 if T5 & 1 else T5 + (T5 >> 1) - T3
            T1 = T1 * T4 % self.p
            y3 = (T1 - T2) % self.p
        else:  # 不同点相加
            # 处理无穷远点
            if P1 == self.O:
                return P2
            if P2 == self.O:
                return P1

            # 根据参数包含的项数判断坐标系（是仿射坐标则转Jacobian坐标）
            x1, y1, z1 = P1 if len(P1) == 3 else (*P1, 1)
            x2, y2, z2 = P2 if len(P2) == 3 else (*P2, 1)

            if z2 != 1 and z1 != 1:
                z1_2 = z1 * z1 % self.p
                z2_2 = z2 * z2 % self.p
                t1 = x1 * z2_2 % self.p
                t2 = x2 * z1_2 % self.p
                t3 = t1 - t2
                z3 = z1 * z2 * t3 % self.p
                if z3 == 0:  # 处理无穷远点
                    return self.O
                t4 = y1 * z2 * z2_2 % self.p
                t5 = y2 * z1 * z1_2 % self.p
                t6 = t4 - t5
                t7 = t1 + t2
                t8 = t4 + t5
                t3_2 = t3 * t3 % self.p
                x3 = (t6 * t6 - t7 * t3_2) % self.p
                t9 = (t7 * t3_2 - (x3 << 1)) % self.p
                y3 = (t9 * t6 - t8 * t3 * t3_2) * self._2 % self.p
            else:  # 可简化计算
                if z1 == 1:  # 确保第二个点的z1=1
                    x1, y1, z1, x2, y2 = x2, y2, z2, x1, y1
                T1 = z1 * z1 % self.p
                T2 = y2 * z1 % self.p
                T3 = x2 * T1 % self.p
                T1 = T1 * T2 % self.p
                T2 = T3 - x1
                z3 = z1 * T2 % self.p
                if z3 == 0:  # 处理无穷远点
                    return self.O
                T3 = T3 + x1
                T1 = T1 - y1
                T4 = T2 * T2 % self.p
                T5 = T1 * T1 % self.p
                T2 = T2 * T4 % self.p
                T3 = T3 * T4 % self.p
                T4 = x1 * T4 % self.p
                x3 = T5 - T3 % self.p
                T2 = y1 * T2 % self.p
                T3 = T4 - x3
                T1 = T1 * T3 % self.p
                y3 = T1 - T2 % self.p
                # T1 = z1 * z1 % self.p
                # T3 = x2 * T1 % self.p
                # T2 = T3 - x1
                # z3 = z1 * T2 % self.p
                # if z3 == 0: # 处理无穷远点
                # return self.O
                # T1 = (T1 * y2 * z1  - y1) % self.p
                # T4 = T2 * T2 % self.p
                # x3 = T1 * T1 - (T3 + x1) * T4 % self.p
                # T1 = T1 * (x1 * T4 - x3) % self.p
                # y3 = T1 - y1 * T2 * T4 % self.p

        return x3, y3, z3

    # Jacobian加重射影坐标下的点乘运算
    # SM2第1部分 A.3
    # 输入点包含两项时为仿射坐标，三项为Jacobian坐标
    # conv=True时结果转换为仿射坐标，否则不转换
    # algo表示选择的算法， r表示算法三（滑动窗法）的窗口值
    def Jacb_multiply(self, k, P, conv=True, algo=2, r=5):
        # 处理无穷远点
        if k == 0 or P == self.O:
            return self.O

        # 仿射坐标转Jacobian坐标
        # if len(P) == 2:
        # P = (*P, 1)

        # 算法一：二进制展开法
        if algo == 1:
            Q = P
            for i in bin(k)[3:]:
                Q = self.Jacb_add(Q)
                if i == '1':
                    Q = self.Jacb_add(Q, P)

        # 算法二：加减法
        elif algo == 2:
            h = bin(3 * k)[2:]
            k = bin(k)[2:]
            k = '0' * (len(h) - len(k)) + k
            Q = P
            minusP = self.minus(P)
            for i in range(1, len(h) - 1):
                Q = self.Jacb_add(Q)
                if h[i] == '1' and k[i] == '0':
                    Q = self.Jacb_add(Q, P)
                elif h[i] == '0' and k[i] == '1':
                    Q = self.Jacb_add(Q, minusP)

        # 算法三：滑动窗法
        # 当k为255/256位时，通过test_r函数测试，r=5复杂度最低
        elif algo == 3:
            k = bin(k)[2:]
            l = len(k)
            if r >= l:  # 如果窗口大于k的二进制位数，则本算法无意义
                return self.Jacb_multiply(int(k, 2), P, conv, 2)

            # 保存P[j]值的字典
            P_ = {1: P, 2: self.Jacb_add(P)}
            for i in range(1, 1 << (r - 1)):
                P_[(i << 1) + 1] = self.Jacb_add(P_[(i << 1) - 1], P_[2])

            t = r
            while k[t - 1] != '1':
                t -= 1
            hj = int(k[:t], 2)
            Q = P_[hj]
            j = t
            while j < l:
                if k[j] == '0':
                    Q = self.Jacb_add(Q)
                    j += 1
                else:
                    t = min(r, l - j)
                    while k[j + t - 1] != '1':
                        t -= 1
                    hj = int(k[j:j + t], 2)
                    Q = self.Jacb_add(self.Jacb_multiply(1 << t, Q, False, 2), P_[hj])
                    j += t

        return self.Jacb_to_affine(Q) if conv else Q

    # Jacobian加重射影坐标转仿射坐标
    # SM2第1部分 A.1.2.3.2
    def Jacb_to_affine(self, P):
        if len(P) == 2:  # 已经是仿射坐标
            return P
        x, y, z = P
        # 处理无穷远点
        if z == 0:
            return self.O
        z_ = get_inverse(z, self.p)  # z的乘法逆元
        x2 = x * z_ * z_ % self.p
        y2 = y * z_ * z_ * z_ % self.p
        return x2, y2

    # 判断是否为无穷远点（零点）
    def is_zero(self, P):
        if len(P) == 2:  # 仿射坐标
            return P == self.O
        else:  # Jacobian加重射影坐标
            return P[2] == 0

    # 判断是否为域Fp中的元素
    # 可输入多个元素，全符合才返回True
    def on_Fp(self, *x):
        for i in x:
            if 0 <= i < self.p:
                pass
            else:
                return False
        return True

    # 判断是否在椭圆曲线上
    def on_curve(self, P):
        if self.is_zero(P):
            return False
        if len(P) == 2:  # 仿射坐标
            x, y = P
            return y * y % self.p == (x * x * x + self.a * x + self.b) % self.p
        else:  # Jacobian加重射影坐标
            x, y, z = P
            return y * y % self.p == (x * x * x + self.a * x * pow(z, 4, self.p) + self.b * pow(z, 6, self.p)) % self.p

    # 生成密钥对
    # 返回值：d为私钥，P为公钥
    # SM2第1部分 6.1
    def gen_keypair(self):
        d = random.randint(1, self.n - 2)
        P = self.Jacb_multiply(d, self.G)
        return d, P

    # 公钥验证
    # SM2第1部分 6.2.1
    def pk_valid(self, P):
        # 判断点P的格式
        if P and len(P) == 2 and type(P[0]) == type(P[1]) == int:
            pass
        else:
            self.error = '格式有误'  # 记录错误信息
            return False
        # a) 验证P不是无穷远点O
        if self.is_zero(P):
            self.error = '无穷远点'
            return False
        # b) 验证公钥P的坐标xP和yP是域Fp中的元素
        if not self.on_Fp(*P):
            self.error = '坐标值不是域Fp中的元素'
            return False
        # c) 验证y^2 = x^3 + ax + b (mod p)
        if not self.on_curve(P):
            self.error = '不在椭圆曲线上'
            return False
        # d) 验证[n]P = O
        if not self.is_zero(self.Jacb_multiply(self.n, P, False)):
            self.error = '[n]P不是无穷远点'
            return False
        return True

    # 确认目前已有公私钥对
    def confirm_keypair(self):
        if not hasattr(self, 'pk') or not self.pk_valid(self.pk) or self.pk != self.Jacb_multiply(self.sk, self.G):
            # 目前没有合格的公私钥对则生成
            while True:
                d, P = self.gen_keypair()
                if self.pk_valid(P):  # 确保公钥通过验证
                    self.sk, self.pk = d, P
                    return
