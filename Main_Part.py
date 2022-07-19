if __name__ == "__main__":
    test_ECDH()
    test_SM2_agreement(True)
    # 可复现SM2文档中的示例结果
    test_signature()
    test_SM2_agreement2(True)
    test_encryption()
