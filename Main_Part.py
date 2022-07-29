#测试主体程序，调用key_Enc_test.py里的代码进行测试

if __name__ == "__main__":
    test_ECDH()
    test_SM2_agreement(True)
    # 运行后可复现SM2文档中的示例结果
    test_signature()
    test_encryption()
