//
//  cryptTool.h
//  welfareAssociation
//
//  Created by yang li on 2019/1/14.
//  Copyright © 2019 GoodSoGood. All rights reserved.
//

#import <Foundation/Foundation.h>
#include <openssl/pem.h>

NS_ASSUME_NONNULL_BEGIN

@interface CryptPublicSecKey : NSObject
@end

@interface CryptPrivateSecKey : NSObject
@end

@interface CryptTool : NSObject

+ (CryptPublicSecKey *)getKey;

/** 创建随机Key */
+ (void)createKeyWithPublicKey:(CryptPublicSecKey **)publicKey privateKey:(CryptPrivateSecKey **)privateKey;

/** 获取公钥Data */
+ (NSData *)getPublicKeyBitsFromPublicKey:(CryptPublicSecKey *)publicKey;
/** 获取公钥Base64String */
+ (NSString *)getPublicKeyBase64StringFromPublicKey:(CryptPublicSecKey *)publicKey;

/** 根据Data创建公钥 */
+ (CryptPublicSecKey *)publicSecKeyFromKeyString:(NSString *)givenString;
+ (CryptPublicSecKey *)publicSecKeyFromKeyBits:(NSData *)givenData;

/** 加密 */
+ (NSData *)encryptWithPublicKey:(CryptPublicSecKey *)publicKey string:(NSString *)plainString;
+ (NSData *)encryptWithPublicKey:(CryptPublicSecKey *)publicKey Data:(NSData *)plainData;

/** 检验 */
+ (BOOL)verifyWithPublicKey:(CryptPublicSecKey *)publicKey SignedData:(NSData *)signedData Signature:(NSData *)signature;

/** 获取私钥Data */
+ (NSData *)getPrivateKeyBitsFromPrivateKey:(CryptPrivateSecKey *)privateKey;
/** 获取私钥Base64String */
+ (NSString *)getPrivateKeyBase64StringFromPrivateKey:(CryptPrivateSecKey *)privateKey;

/** 根据Data创建私钥 */
+ (CryptPrivateSecKey *)privateSecKeyFromKeyString:(NSString *)givenString;
+ (CryptPrivateSecKey *)privateSecKeyFromKeyBits:(NSData *)givenData;

/** 解密 */
+ (NSData *)decryptWithPrivateKey:(CryptPrivateSecKey *)privateKey Data:(NSData *)cipherData;

/** 签名 */
+ (NSData *)signWithPrivateKey:(CryptPrivateSecKey *)privateKey Data:(NSData *)data;

/** RC4加密 */
+ (NSData *)rc4EncryptWithKey:(NSString *)key String:(NSString *)string;
+ (NSData *)rc4EncryptWithKey:(NSString *)key Data:(NSData *)data;

/** RC4解密 */
+ (NSData *)rc4DecryptWithKey:(NSString *)key Data:(NSData *)data;

/** 16进制转NSData */
+ (NSData *)convertHexStrToData:(NSString *)str;

@end

NS_ASSUME_NONNULL_END
