# Project-impl-sm2-with-RFC6979
按协议RFC6979实现SM2。

一、ECDSA概述
 
  椭圆曲线数字签名算法（ECDSA）是使用椭圆曲线密码（ECC）对数字签名算法（DSA）的模拟。与普通的离散对数问题（DLP）和大数分解问题（IFP）不同，椭圆曲线离散对数问题没有亚指数时间的解决方法。因此椭圆曲线密码的单位比特强度要高于其他公钥体制。
数字签名算法（DSA）在联邦信息处理标准FIPS中有详细论述，称为数字签名标准。它的安全性基于素域上的离散对数问题。可以看作是椭圆曲线对先前离散对数问题（DLP）的密码系统的模拟，只是群元素由素域中的元素数换为有限域上的椭圆曲线上的点。椭圆曲线离散对数问题远难于离散对数问题，单位比特强度要远高于传统的离散对数系统。因此在使用较短的密钥的情况下，ECC可以达到于DL系统相同的安全级别。这带来的好处就是计算参数更小，密钥更短，运算速度更快，签名也更加短小。【1】

二、ECDSA原理【2】

  ECDSA是ECC与DSA的结合，整个签名过程与DSA类似，所不一样的是签名中采取的算法为ECC，最后签名出来的值也是分为r,s。
签名过程如下：
1、选择一条椭圆曲线Ep(a,b)，和基点G；

2、选择私有密钥k（k<n，n为G的阶），利用基点G计算公开密钥K=kG；

3、产生一个随机整数r（r<n），计算点R=rG；

4、将原数据和点R的坐标值x,y作为参数，计算SHA1做为hash，即Hash=SHA1(原数据,x,y)；

5、计算s≡r - Hash * k (mod n)

6、r和s做为签名值，如果r和s其中一个为0，重新从第3步开始执行

验证过程如下：

1、接受方在收到消息(m)和签名值(r,s)后，进行以下运算

2、计算：sG+H(m)P=(x1,y1), r1≡ x1 mod p。

3、验证等式：r1 ≡ r mod p。

4、如果等式成立，接受签名，否则签名无效。

三.SM2加密与签名认证

  SM2算法是国家密码管理局于2010年12月颁布的中国商用公钥密码标准算法。SM2基于椭圆曲线离散对数问题，计算复杂度是指数级（暂未发现亚指数级或多项式级的计算方法），相较于广泛应用的RSA公钥密码算法，在同等安全程度要求下，SM2所需密钥长度小、处理速度快。由于SM2在安全性、运算性能等方面都优于RSA算法，且具有自主知识产权，我国计划在商用密码体系中用SM2替换RSA算法。【3】椭圆曲线密码（ECC）的安全性明显强于RSA，该结论参考知乎用户@Datacruier,列出对比表格。
  
![图片](https://user-images.githubusercontent.com/107350922/179737106-c120bb2b-482b-4171-a516-0642fda49778.png)
![图片](https://user-images.githubusercontent.com/107350922/179737130-355099e0-4b29-4155-8373-c6ae89f393a1.png)

  在依据RFC6979规定的标准，对于SM2方案的实现采用Python语言编写的国密工具包主要是gmssl-python库和snowland-smx-python（pysmx）库，二者较为完整地实现了SM2、SM3、SM4等国密算法。本工具包涉及的散列运算使用了pysmx库的SM3算法，pysmx库对SM3算法的实现高效而优雅，在此向pysmx库的作者致以诚挚的敬意和感谢！

相较于现有Python国密算法工具包的SM2模块，本工具包的优势主要体现在以下3个方面：

1. 首次开源SM2密钥协商算法。gmssl库和pysmx库仅实现了SM2签名和验证、加密和解密算法，没有实现SM2密钥协商算法，互联网上也未找到实现SM2密钥协商算法的Python代码，故本工具包是首次在互联网上开源SM2密钥协商算法的Python代码。【4】

2. 算法实现更为健壮和完整。gmssl库和pysmx库中的椭圆曲线点乘算法仅能输入有限域内的乘数（否则报错），所实现的SM2签名/验证算法不包含标准要求的Z值计算和Hash变换，除核心算法（密钥生成、签名、验证、加密、解密等）之外还缺少标准描述的一些辅助算法，gmssl库仅能输入bytes类型消息；本工具包的点乘算法能够输入任意自然数作为乘数并保证正确性，SM2签名/验证算法完整实现了Z值计算和Hash变换，除核心算法之外还实现了标准描述的一些重要辅助函数（如公钥验证、椭圆曲线系统参数验证等）。

3. 性能更佳。本工具包通过采用更高效的点乘算法、减少数据类型转换、充分运用算术运算加速技巧等途径，明显提高了计算效率。以SM2算法耗时的主要来源——椭圆曲线点乘运算为例进行测试，同等条件下本工具包的平均耗时约为gmssl库的35.5%、pysmx库的61.8%，实际运行签名与验证、加解密等算法同样具备上述幅度的性能优势。【5】

四.代码文件说明：

complete submission是所有工作量的集合版，由于是分功能实现SM2相关的部件，所以进行的了分块的提交。
 
首先对于SM体系下的椭圆曲线加解密体系，实现了一个ECC—class,椭圆曲线密码类（实现一般椭圆曲线的运算，不局限于SM2）。该实现思路参考【6】。

对于SM2-class，则是调用了ECC—class作为底层运算部件，根据RFC6979协议标准实现。该方案进行了基础性的ECDH正确性测试，SM2密钥协商测试，SM2数字签名与验证测试，测试过程均在key-Enc-test文件中可运行。

最后main_part运行结果，可复现RFC6979，SM2文档中的示例结果（达到要求）

备注：若要完整运行测试代码还需安装gmssl（pip install gmssl）和pysmx（pip install snowland-smx）。

参考文献：
【1】：https://zhuanlan.zhihu.com/p/455030060

【2】：https://zhuanlan.zhihu.com/p/442141489

【3】：https://baike.baidu.com/item/SM2/15081831?fr=aladdin

【4】：https://zhuanlan.zhihu.com/p/347750862

【5】：国家密码管理局关于发布《SM2椭圆曲线公钥密码算法》公告[EB/OL]．(2010-12-17) [2022-02-20]．https://sca.gov.cn/sca/xwdt/2010-12/17/content_1002386.shtml．

【6】：https://gitee.com/basddsa/hggm

