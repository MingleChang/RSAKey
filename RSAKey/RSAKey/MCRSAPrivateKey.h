//
//  MCRSAPrivateKey.h
//  RSAKey
//
//  Created by MingleChang on 2019/7/16.
//  Copyright © 2019 MingleChang. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <openssl/pem.h>
NS_ASSUME_NONNULL_BEGIN

@interface MCRSAPrivateKey : NSObject

- (instancetype)initWithRSA:(RSA *)rsa;
- (instancetype)initWithData:(NSData *)data;

+ (MCRSAPrivateKey *)privateKeyWithData:(NSData *)data;
+ (MCRSAPrivateKey *)privateKeyWithBase64Data:(NSData *)data;
+ (MCRSAPrivateKey *)privateKeyWithBase64String:(NSString *)string;

- (NSData *)dataValue;

- (NSData *)decryptWithPKCS1Padding:(NSData *)cipherData error:(NSError **)error;
- (NSData *)signWithSHA256:(NSData *)message error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
