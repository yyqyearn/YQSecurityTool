//
//  YQSecurityTool.m
//  下载
//
//  Created by yyq on 15/12/7.
//  Copyright © 2015年 WX. All rights reserved.
//

#import "YQSecurityTool.h"
//#import "NSData+YQAES.h"
//#define gIv @"xxxxxxxxxxxxxxxx" //为与安卓互通，选择kCCOptionECBMode时无效

@implementation YQSecurityTool

#pragma mark - 公共方法

+ (NSString*)encryptAESDataWithString:(NSString*)string
                                  key:(NSString *)key
                            algorithm:(AESAlg)algorithm
                               AESBit:(AESBit)aesBit
                                  gIv:(NSString*)gIv
{
    //将NSString转化为NSData
    NSData *data = [string dataUsingEncoding:NSUTF8StringEncoding];
    //使用密码对nsdata进行加密
    NSData *encryptedData = [YQSecurityTool AESEncryptWithData:data key:key algorithm:algorithm AESBit:aesBit gIv:gIv];
    
    return [encryptedData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    
}

+ (NSString*)decryptAESDataWithString:(NSString*)string
                                  key:(NSString *)key
                            algorithm:(AESAlg)algorithm
                               AESBit:(AESBit)aesBit
                                  gIv:(NSString*)gIv

{
    //将NSString转化为NSData
    NSData *data = [[NSData alloc]initWithBase64EncodedString:string options:NSDataBase64DecodingIgnoreUnknownCharacters];
    //使用密码对data进行解密
    NSData *decryData = [YQSecurityTool AESDecryptWithData:data key:key algorithm:algorithm AESBit:aesBit gIv:gIv];
    //将解了密码的nsdata转化为nsstring
    NSString *str = [[NSString alloc] initWithData:decryData encoding:NSUTF8StringEncoding];
    return str;

}


+ (NSString*)encryptAESDataString:(NSString*)string app_key:(NSString*)key
{
    //将NSString转化为NSData
    NSData *data = [string dataUsingEncoding:NSUTF8StringEncoding];
    //使用密码对nsdata进行加密
    NSData *encryptedData = [YQSecurityTool AES128EncryptWithData:data key:key];
//    NSLog(@"加密后的字符串 :%@",[encryptedData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength]);
    
    return [encryptedData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
}


+ (NSString*)decryptAESDataString:(NSString*)string app_key:(NSString*)key
{
    
    NSData *data = [[NSData alloc]initWithBase64EncodedString:string options:NSDataBase64DecodingIgnoreUnknownCharacters];
    //使用密码对data进行解密
    NSData *decryData = [YQSecurityTool AES128DecryptWithData:data key:key];
    //将解了密码的nsdata转化为nsstring
    NSString *str = [[NSString alloc] initWithData:decryData encoding:NSUTF8StringEncoding];
//    NSLog(@"解密后的字符串 :%@",str);
    return str;
}




#pragma mark - 私有方法

+ (NSData *)AESEncryptWithData:(NSData*)data
                           key:(NSString *)key
                     algorithm:(AESAlg)algorithm
                        AESBit:(AESBit)aesBit
                           gIv:(NSString*)gIv
{
    
    NSInteger kCCKeySize = 0;
    switch (aesBit) {
        case AESBit128:
            kCCKeySize = kCCKeySizeAES128;
            break;
        case AESBit256:
            kCCKeySize = kCCKeySizeAES256;
            break;
        default:
            kCCKeySize = kCCKeySizeAES128;//默认
            break;
    }
    CCOptions aCcOptions;
    switch (algorithm) {
        case AESAlgCBC:
            aCcOptions = kCCOptionPKCS7Padding;
            break;
        case AESAlgEBC:
            aCcOptions = kCCOptionPKCS7Padding|kCCOptionECBMode;
            break;
        default:
            aCcOptions = kCCOptionPKCS7Padding; //默认CBC
            break;
    }

    char keyPtr[kCCKeySize+1];
    bzero(keyPtr, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    char ivPtr[kCCKeySize+1];
    memset(ivPtr, 0, sizeof(ivPtr));
    [gIv getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = [data length];
    
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    size_t numBytesEncrypted = 0;
    
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt,
                                          kCCAlgorithmAES128,
                                          aCcOptions,
                                          keyPtr,
                                          kCCKeySize,
                                          ivPtr,
                                          [data bytes],
                                          dataLength,
                                          buffer,
                                          bufferSize,
                                          &numBytesEncrypted);
    if (cryptStatus == kCCSuccess) {
        return [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
    }
    free(buffer);
    return nil;
}


+ (NSData *)AESDecryptWithData:(NSData*)data
                           key:(NSString *)key
                     algorithm:(AESAlg)algorithm
                        AESBit:(AESBit)aesBit
                           gIv:(NSString*)gIv
{
    NSInteger kCCKeySize = 0;
    switch (aesBit) {
        case AESBit128:
            kCCKeySize = kCCKeySizeAES128;
            break;
        case AESBit256:
            kCCKeySize = kCCKeySizeAES256;
            break;
        default:
            kCCKeySize = kCCKeySizeAES128;//默认
            break;
    }
    
    CCOptions aCcOptions;
    switch (algorithm) {
        case AESAlgCBC:
            aCcOptions = kCCOptionPKCS7Padding;
            break;
        case AESAlgEBC:
            aCcOptions = kCCOptionPKCS7Padding|kCCOptionECBMode;
            break;
        default:
            aCcOptions = kCCOptionPKCS7Padding; //默认CBC
            break;
    }
    
    char keyPtr[kCCKeySize+1];
    bzero(keyPtr, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    char ivPtr[kCCKeySize+1];
    memset(ivPtr, 0, sizeof(ivPtr));
    [gIv getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = [data length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    size_t numBytesDecrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                          kCCAlgorithmAES128,
                                          aCcOptions,
                                          keyPtr,
                                          kCCKeySize,
                                          ivPtr,
                                          [data bytes],
                                          dataLength,
                                          buffer,
                                          bufferSize,
                                          &numBytesDecrypted);
    if (cryptStatus == kCCSuccess) {
        return [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
    }
    free(buffer);
    return nil;
}






+ (NSData *)AES128EncryptWithData:(NSData*)data key:(NSString *)key//加密
{
    return [YQSecurityTool AESEncryptWithData:data key:key algorithm:AESAlgCBC AESBit:AESBit128 gIv:nil];
}


+ (NSData *)AES128DecryptWithData:(NSData*)data key:(NSString *)key//解密
{
    return [YQSecurityTool AESDecryptWithData:data key:key algorithm:AESAlgCBC AESBit:AESBit128 gIv:nil];
}

- (NSData *)AES256EncryptWithData:(NSData*)data key:(NSString *)key
{
    return [YQSecurityTool AESEncryptWithData:data key:key algorithm:AESAlgCBC AESBit:AESBit256 gIv:nil];
}

- (NSData *)AES256DecryptWithData:(NSData*)data key:(NSString *)key
{
    return [YQSecurityTool AESEncryptWithData:data key:key algorithm:AESAlgCBC AESBit:AESBit256 gIv:nil];
}


@end
