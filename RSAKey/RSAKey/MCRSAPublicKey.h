//
//  MCRSAPublicKey.h
//  RSAKey
//
//  Created by MingleChang on 2019/7/16.
//  Copyright © 2019 MingleChang. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <openssl/pem.h>
NS_ASSUME_NONNULL_BEGIN

@interface MCRSAPublicKey : NSObject

- (instancetype)initWithRSA:(RSA *)rsa;
- (instancetype)initWithData:(NSData *)data;

+ (MCRSAPublicKey *)publicKeyWithData:(NSData *)data;
+ (MCRSAPublicKey *)publicKeyWithBase64Data:(NSData *)data;
+ (MCRSAPublicKey *)publicKeyWithBase64String:(NSString *)string;

- (NSData *)dataValue;

- (NSData *)encryptWithPKCS1Padding:(NSData *)messageData error:(NSError **)error;
- (BOOL)verifySignatureWithSHA256:(NSData *)signature message:(NSData *)message;

@end

NS_ASSUME_NONNULL_END
