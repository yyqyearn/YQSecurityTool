//
//  YQSecurityTool.h
//  下载
//
//  Created by yyq on 15/12/7.
//  Copyright © 2015年 WX. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>


@interface YQSecurityTool : NSObject

#pragma mark - AES加密
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
