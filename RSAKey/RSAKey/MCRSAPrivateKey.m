//
//  MCRSAPrivateKey.m
//  RSAKey
//
//  Created by MingleChang on 2019/7/16.
//  Copyright © 2019 MingleChang. All rights reserved.
//

#import "MCRSAPrivateKey.h"

@interface MCRSAPrivateKey()

@property (nonatomic, assign)RSA *rsa;

@end

@implementation MCRSAPrivateKey
- (instancetype)initWithRSA:(RSA *)rsa {
    self = [super init];
    if (self) {
        CRYPTO_add(&rsa->references, 1, CRYPTO_LOCK_RSA);
        self.rsa = rsa;
    }
    return self;
}
- (instancetype)initWithData:(NSData *)data {
    self = [super init];
    if (self) {
        BIO *privateBIO = BIO_new_mem_buf((void *) data.bytes, (int)data.length);
        EVP_PKEY *pkey = EVP_PKEY_new();
        @try {
            if (!PEM_read_bio_PrivateKey(privateBIO, &pkey, 0, NULL)) {
                NSAssert(NO, nil);
            }
            self.rsa = EVP_PKEY_get1_RSA(pkey);
        }
        @finally {}
    }
    return self;
}
+ (MCRSAPrivateKey *)privateKeyWithData:(NSData *)data {
    return [[MCRSAPrivateKey alloc] initWithData:data];
}
+ (MCRSAPrivateKey *)privateKeyWithBase64Data:(NSData *)data {
    NSString *lPem = [data base64EncodedStringWithOptions:64];
    lPem = [NSString stringWithFormat:@"-----BEGIN RSA PRIVATE KEY-----\n%@\n-----END RSA PRIVATE KEY-----", lPem];
    NSData *lData = [lPem dataUsingEncoding:NSUTF8StringEncoding];
    return [MCRSAPrivateKey privateKeyWithData:lData];
}
+ (MCRSAPrivateKey *)privateKeyWithBase64String:(NSString *)string {
    NSData *lData = [[NSData alloc] initWithBase64EncodedString:string options:NSDataBase64DecodingIgnoreUnknownCharacters];
    return [MCRSAPrivateKey privateKeyWithBase64Data:lData];
}
- (NSData *)dataValue {
    EVP_PKEY *pkey = EVP_PKEY_new();
    char *privateBytes;
    int privateBytesLength;
    @try {
        EVP_PKEY_set1_RSA(pkey, self.rsa);
        BIO *privateBIO = BIO_new(BIO_s_mem());
        PEM_write_bio_PKCS8PrivateKey(privateBIO, pkey, NULL, NULL, 0, 0, NULL);
        privateBytesLength =  BIO_pending(privateBIO);
        privateBytes = malloc((size_t)privateBytesLength);
        BIO_read(privateBIO, privateBytes, privateBytesLength);
    }
    @finally {
        EVP_PKEY_free(pkey);
    }
    
    NSData *rawDataValue = [NSData dataWithBytesNoCopy:privateBytes length:privateBytesLength];
    NSMutableString *dataString = [[NSMutableString alloc] initWithData:rawDataValue encoding:NSUTF8StringEncoding];
    
    NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:@"(-{5,}BEGIN (RSA )?PRIVATE KEY-{5,})|(-{5,}END (RSA )?PRIVATE KEY-{5,})|\n" options:0 error:nil];
    [regex replaceMatchesInString:dataString options:0 range:NSMakeRange(0, dataString.length) withTemplate:@""];
    
    return [[NSData alloc] initWithBase64EncodedString:dataString options:NSDataBase64DecodingIgnoreUnknownCharacters];
}
- (NSData *)decryptWithPKCS1Padding:(NSData *)cipherData error:(NSError **)error {
    NSUInteger rsaSize = (NSUInteger) RSA_size(self.rsa);
    NSMutableData *messageData = [NSMutableData dataWithLength:rsaSize];
    int messageBytesLength = RSA_private_decrypt((int)cipherData.length, cipherData.bytes, messageData.mutableBytes, self.rsa, RSA_PKCS1_PADDING);
    if (messageBytesLength < 0) {
        if (error) {
            *error = [NSError errorWithDomain:@"OpenSSL Error" code:-1 userInfo:@{}];
        }
        return nil;
    }
    [messageData setLength:(NSUInteger) messageBytesLength];
    
    return messageData;
}

- (NSData *)signWithSHA256:(NSData *)message error:(NSError **)error {
    SHA256_CTX sha256Ctx;
    unsigned char messageDigest[SHA256_DIGEST_LENGTH];
    if (!SHA256_Init(&sha256Ctx)) {
        if (error) *error = [NSError errorWithDomain:@"OpenSSL Error" code:-1 userInfo:@{}];
        return nil;
    }
    if (!SHA256_Update(&sha256Ctx, message.bytes, message.length)) {
        if (error) *error = [NSError errorWithDomain:@"OpenSSL Error" code:-1 userInfo:@{}];
        return nil;
    }
    if (!SHA256_Final(messageDigest, &sha256Ctx)) {
        if (error) *error = [NSError errorWithDomain:@"OpenSSL Error" code:-1 userInfo:@{}];
        return nil;
    }
    NSMutableData *signature = [NSMutableData dataWithLength:(NSUInteger) RSA_size(_rsa)];
    unsigned int signatureLength = 0;
    if (RSA_sign(NID_sha256, messageDigest, SHA256_DIGEST_LENGTH, signature.mutableBytes, &signatureLength, _rsa) == 0) {
        if (error)
            *error = [NSError errorWithDomain:@"OpenSSL Error" code:-1 userInfo:@{}];
        return nil;
    }
    [signature setLength:(NSUInteger) signatureLength];
    
    return signature;
}
@end
