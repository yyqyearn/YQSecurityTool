# YQSecurityTool
一个简单的AES128加密工具

引入头文件
import "YQSecurityTool.h"



事务方法：

    NSString * originalString = @"originalString";
    NSString * key = @"key";
    
    NSString *encryptionString = [YQSecurityTool encryptAESDataString:originalString app_key:key];

    NSString *decryptionString = [YQSecurityTool decryptAESDataString:encryptionString app_key:key];

    NSLog(@"加密前 = %@  ，加密后 = %@  ，解密后 = %@",originalString,encryptionString,decryptionString);


