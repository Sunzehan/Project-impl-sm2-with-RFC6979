# 基础性的ECDH正确性测试
def test_ECDH(verify=False):
    time_1 = get_cpu_time()
    sm2 = SM2(genkeypair=False)
    # A、B双方生成公、私钥
    dA, PA = sm2.gen_keypair()
    dB, PB = sm2.gen_keypair()
    # 验证ECC系统参数和公钥
    if verify:
        if not sm2.para_valid():
            print('椭圆曲线系统参数未通过验证：%s' % sm2.error)
            return
        if not sm2.pk_valid(PA):
            print('PA未通过验证：%s' % sm2.error)
            return
        if not sm2.pk_valid(PB):
            print('PB未通过验证：%s' % sm2.error)
            return

    # A将PA传给B，B将PB传给A

    # A、B双方计算密钥
    QA = sm2.Jacb_multiply(dA, PB)
    KA = KDF(to_byte(QA), KEY_LEN)
    QB = sm2.Jacb_multiply(dB, PA)
    KB = KDF(to_byte(QB), KEY_LEN)
    time_2 = get_cpu_time()
    print('ECDH密钥协商完毕，耗时%.2f ms' % ((time_2 - time_1) * 1000))
    print('KA == KB?: %s, value: 0x%s, len: %d' % (KA == KB, KA.hex(), len(KA) << 3))


# SM2密钥协商测试
# 模拟真实的网络环境环境，可以使用PC搭建一个模拟服务器
def test_SM2_agreement(option=False):
    time_1 = get_cpu_time()
    # A、B双方初始化
    sm2_A = SM2(ID='sunzehan')
    sm2_B = SM2(ID='Jimmy')
    # A、B均掌握对方的公钥和ID
    PA, IDA = sm2_A.pk, sm2_A.ID
    PB, IDB = sm2_B.pk, sm2_B.ID

    # A 发起协商
    rA, RA = sm2_A.agreement_initiate()
    # A将RA发送给B

    # B 响应协商
    res, content = sm2_B.agreement_response(RA, PA, IDA, option)
    if not res:
        print('B报告协商错误：', content)
        return
    if option:
        RB, KB, SB, S2 = content
    else:
        RB, KB = content
        SB = None
    # B将RB、(选项SB)发送给A

    # A 协商确认
    res, content = sm2_A.agreement_confirm(rA, RA, RB, PB, IDB, SB, option)
    if not res:
        print('A报告协商错误：', content)
        return
    if option:
        KA, SA = content
    else:
        KA = content

    if option:
        # A将(选项SA)发送给B
        # B 协商确认
        res, content = sm2_B.agreement_confirm2(S2, SA)
        if not res:
            print('B报告协商错误：', content)
            return
    time_2 = get_cpu_time()
    print('SM2密钥协商完毕，耗时%.2f ms' % ((time_2 - time_1) * 1000))
    print('KA == KB?: %s, value: 0x%s, len: %d' % (KA == KB, KA.hex(), len(KA) << 3))


# SM2示例中的椭圆曲线系统推荐参数
def security_para():
    p = 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
    a = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
    b = 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
    xG = 0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
    yG = 0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2
    n = 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7
    G = (xG, yG)
    h = 1
    return p, a, b, n, G, h


# SM2数字签名与验证测试
# SM2第2部分 A.1 A.2
def test_signature():
    IDA = 'ALICE123@YAHOO.COM'
    M = 'message digest'
    dA = 0x128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263
    xA = 0x0AE4C7798AA0F119471BEE11825BE46202BB79E2A5844495E97C04FF4DF2548A
    yA = 0x7C0240F88F1CD4E16352A73C17B7F16F07353E53A176D684A9FE0C6BB798E857
    PA = (xA, yA)
    k = 0x6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F

    # A、B双方初始化
    sm2_A = SM2(*security_para(), IDA, dA, PA)
    sm2_B = SM2(*security_para())

    time_1 = get_cpu_time()
    # A对消息M进行签名
    sig = sm2_A.sign(M, k)

    # A将消息M签名(r, s)发送给B

    # B对消息M签名进行验证
    res = sm2_B.verify(M, sig, IDA, PA)
    time_2 = get_cpu_time()
    print('SM2签名、验证完毕，耗时%.2f ms' % ((time_2 - time_1) * 1000))
    print('结果：%s，R值：%s' % (res, sig[:sm2_A.keysize].hex()))
    # 验证通过，输出的r值(40f1ec59f793d9f49e09dcef49130d4194f79fb1eed2caa55bacdb49c4e755d1)与SM2第2部分 A.2中的结果一致


# SM2密钥协商测试2
# SM2第3部分 A.1 A.2
def test_SM2_agreement2(option=False):
    IDA = 'sunzehan3@sina.com'
    IDB = 'Jimmysun@163.com'
    dA = 0x6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE
    xA = 0x3099093BF3C137D8FCBBCDF4A2AE50F3B0F216C3122D79425FE03A45DBFE1655
    yA = 0x3DF79E8DAC1CF0ECBAA2F2B49D51A4B387F2EFAF482339086A27A8E05BAED98B
    PA = (xA, yA)
    dB = 0x5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53
    xB = 0x245493D446C38D8CC0F118374690E7DF633A8A4BFB3329B5ECE604B2B4F37F43
    yB = 0x53C0869F4B9E17773DE68FEC45E14904E0DEA45BF6CECF9918C85EA047C60A4C
    PB = (xB, yB)
    rA = 0x83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563
    x1 = 0x6CB5633816F4DD560B1DEC458310CBCC6856C09505324A6D23150C408F162BF0
    y1 = 0x0D6FCF62F1036C0A1B6DACCF57399223A65F7D7BF2D9637E5BBBEB857961BF1A
    RA = (x1, y1)
    rB = 0x33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80
    x2 = 0x1799B2A2C778295300D9A2325C686129B8F2B5337B3DCF4514E8BBC19D900EE5
    y2 = 0x54C9288C82733EFDF7808AE7F27D0E732F7C73A7D9AC98B7D8740A91D0DB3CF4
    RB = (x2, y2)

    time_1 = get_cpu_time()
    # A、B双方初始化
    sm2_A = SM2(*security_para(), IDA, dA, PA)
    sm2_B = SM2(*security_para(), IDB, dB, PB)

    # A 发起协商
    # A生成rA, RA，将RA发送给B

    # B 响应协商
    res, content = sm2_B.agreement_response(RA, PA, IDA, option, rB, RB)
    if not res:
        print('B报告协商错误：', content)
        return
    if option:
        RB, KB, SB, S2 = content
    else:
        RB, KB = content
        SB = None
    # B将RB、(选项SB)发送给A

    # A 协商确认
    res, content = sm2_A.agreement_confirm(rA, RA, RB, PB, IDB, SB, option)
    if not res:
        print('A报告协商错误：', content)
        return
    if option:
        KA, SA = content
    else:
        KA = content

    if option:
        # A将(选项SA)发送给B
        # B 协商确认
        res, content = sm2_B.agreement_confirm2(S2, SA)
        if not res:
            print('B报告协商错误：', content)
            return
    time_2 = get_cpu_time()
    print('SM2密钥协商完毕，耗时%.2f ms' % ((time_2 - time_1) * 1000))
    print('KA == KB?: %s, value: 0x%s, len: %d' % (KA == KB, KA.hex(), len(KA) << 3))
    # 输出结果我们发现输出的密钥(55b0ac62a6b927ba23703832c853ded4)，
    # 与SM2第3部分 A.2中的密钥结果一致，说明协商成功，


# SM2加解密测试
# SM2第4部分 A.1 A.2
def test_encryption():
    M = 'encryption standard'
    dB = 0x1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0
    xB = 0x435B39CCA8F3B508C1488AFC67BE491A0F7BA07E581A0E4849A5CF70628A7E0A
    yB = 0x75DDBA78F15FEECB4C7895E2C1CDF5FE01DEBB2CDBADF45399CCF77BBA076A42
    PB = (xB, yB)
    k = 0x4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F

    # A、B双方初始化
    sm2_A = SM2(*security_para())
    sm2_B = SM2(*security_para(), '', dB, PB)

    time_1 = get_cpu_time()
    # A用B的公钥对消息M进行加密
    res, C = sm2_A.encrypt(M, PB, k)
    if not res:
        print('A报告加密错误：', C)
        return

    # A将密文C发送给B

    # B用自己的私钥对密文C进行解密
    res, M2 = sm2_B.decrypt(C)
    if not res:
        print('B报告解密错误：', M2)
        return
    time_2 = get_cpu_time()
    print('SM2加解密完成，耗时%.2f ms' % ((time_2 - time_1) * 1000))
    print('结果：%s，解密得：%s(%s)' % (res, M2.hex(), M2.decode()))
    
    # 加解密成功，解密后的16进制值(656e6372797074696f6e207374616e64617264)与SM2第4部分 A.2中的结果一致
