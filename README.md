# YQSecurityTool
一个简单的AES加密工具
提供128/256位加密
提供ECB/CBC算法加密

引入头文件
import "YQSecurityTool.h"



事务方法：

    NSString * originalString = @"1234567890123456";
    NSString * key = @"haha";
    AESAlg alg = AESAlgEBC;
    AESBit bit = AESBit128;
    NSString * gIv = @"heyhey";
    
    NSString *encryptionString = [YQSecurityTool encryptAESDataWithString:originalString
                                                                      key:key
                                                                algorithm:alg
                                                                   AESBit:bit
                                                                      gIv:gIv
                                  ];
    
    NSString *decryptionString = [YQSecurityTool decryptAESDataWithString:encryptionString
                                                                      key:key
                                                                algorithm:alg
                                                                   AESBit:bit
                                                                      gIv:gIv
                                  ];
    NSLog(@"\n加密前 = %@\n加密后 = %@\n解密后 = %@\nkey = %@\ngIv = %@",
          originalString,
          encryptionString,
          decryptionString,
          key,
          gIv
          );


