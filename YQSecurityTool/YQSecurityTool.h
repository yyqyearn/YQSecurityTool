//
//  YQSecurityTool.h
//  下载
//
//  Created by yyq on 15/12/7.
//  Copyright © 2015年 yyq. All rights reserved.
//




#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>

/**
 *  加密位选项
 */
typedef NS_ENUM(NSUInteger,AESBit) {
    /**
     *  128位
     */
    AESBit128 = 0,
    /**
     *  256位
     */
    AESBit256
};

/**
 *  加密算法
 */
typedef NS_ENUM(NSUInteger, AESAlg) {
    /**
     *  CBC
     */
    AESAlgCBC = 0,
    /**
     *  EBC
     */
    AESAlgEBC
};



@interface YQSecurityTool : NSObject

#pragma mark - AES加密


/**
 *  将string转成AES加密的String
 *
 *  @param string    需要加密的String
 *  @param key       加密的Key(解密时需保持一致)
 *  @param algorithm 加密算法 AESAlgCBC/AESAlgEBC
 *  @param aesBit    加密的位数128/256
 *  @param gIv       加密偏移量，在ECB模式下无效
 *
 *  @return 加密的String/失败为nil
 */
+ (NSString*)encryptAESDataWithString:(NSString*)string
                                  key:(NSString *)key
                            algorithm:(AESAlg)algorithm
                               AESBit:(AESBit)aesBit
                                  gIv:(NSString*)gIv;


/**
 *  将AES加密的String解密成原始String
 *
 *  @param string    需要解密的AESString
 *  @param key       解密的Key(需与加密时的key保持一致)
 *  @param algorithm 加密的算法
 *  @param aesBit    加密的位数128/256
 *  @param gIv       加密偏移量，在ECB模式下无效
 *
 *  @return 解密之后的String/失败为nil
 */
+ (NSString*)decryptAESDataWithString:(NSString*)string
                                  key:(NSString *)key
                            algorithm:(AESAlg)algorithm
                               AESBit:(AESBit)aesBit
                                  gIv:(NSString*)gIv;






/**
 *  将string转成AES加密的String
 *
 *  @param string 需要加密的String
 *  @param key    加密的Key(解密时需保持一致)
 *
 *  @return 加密的String/失败为nil
 */
+ (NSString*)encryptAESDataString:(NSString*)string app_key:(NSString*)key;



/**
 *  将AES加密的String解密成原始String
 *
 *  @param string 需要解密的AESString
 *  @param key    解密的Key(需与加密时的key保持一致)
 *
 *  @return 解密之后的String/失败为nil
 */
+ (NSString*)decryptAESDataString:(NSString*)string app_key:(NSString*)key;




@end
