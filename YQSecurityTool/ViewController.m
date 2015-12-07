//
//  ViewController.m
//  YQSecurityTool
//
//  Created by yyq on 15/12/7.
//  Copyright © 2015年 mobilenow. All rights reserved.
//

#import "ViewController.h"
#import "YQSecurityTool.h"
@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];

    
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
}


@end
