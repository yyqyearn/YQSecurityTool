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

    
    NSString * originalString = @"originalString";
    NSString * key = @"key";
    
    NSString *encryptionString = [YQSecurityTool encryptAESDataString:originalString app_key:key];
    
    NSString *decryptionString = [YQSecurityTool decryptAESDataString:encryptionString app_key:key];
    NSLog(@"加密前 = %@  ，加密后 = %@  ，解密后 = %@",originalString,encryptionString,decryptionString);
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
