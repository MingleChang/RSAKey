//
//  MCRSAPublicKey.m
//  RSAKey
//
//  Created by MingleChang on 2019/7/16.
//  Copyright © 2019 MingleChang. All rights reserved.
//

#import "MCRSAPublicKey.h"
#import <openssl/pem.h>
@interface MCRSAPublicKey ()
@property (nonatomic, assign)RSA *rsa;
@end
@implementation MCRSAPublicKey
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
        BIO *pBIO = BIO_new_mem_buf((void *)data.bytes, (int)data.length);
        EVP_PKEY *pkey = EVP_PKEY_new();
        @try {
            if (!PEM_read_bio_PUBKEY(pBIO, &pkey, NULL, NULL)) {
                NSAssert(NO, nil);
            }
            self.rsa = EVP_PKEY_get1_RSA(pkey);
        }
        @finally{}
    }
    return self;
}

+ (MCRSAPublicKey *)publicKeyWithData:(NSData *)data {
    return [[MCRSAPublicKey alloc] initWithData:data];
}
+ (MCRSAPublicKey *)publicKeyWithBase64Data:(NSData *)data {
    NSString *lPem = [data base64EncodedStringWithOptions:64];
    lPem = [NSString stringWithFormat:@"-----BEGIN PUBLIC KEY-----\n%@\n-----END PUBLIC KEY-----", lPem];
    NSData *lData = [lPem dataUsingEncoding:NSUTF8StringEncoding];
    return [MCRSAPublicKey publicKeyWithData:lData];
}
+ (MCRSAPublicKey *)publicKeyWithBase64String:(NSString *)string {
    NSData *lData = [[NSData alloc] initWithBase64EncodedString:string options:NSDataBase64DecodingIgnoreUnknownCharacters];
    return [MCRSAPublicKey publicKeyWithBase64Data:lData];
}

- (NSData *)dataValue {
    EVP_PKEY *pkey = EVP_PKEY_new();
    char *publicBytes;
    size_t publicBytesLength;
    @try {
        EVP_PKEY_set1_RSA(pkey, self.rsa);
        
        BIO *publicBIO = BIO_new(BIO_s_mem());
        PEM_write_bio_PUBKEY(publicBIO, pkey);
        publicBytesLength = (size_t) BIO_pending(publicBIO);
        publicBytes = malloc(publicBytesLength);
        BIO_read(publicBIO, publicBytes, (int)publicBytesLength);
    }
    @finally {
        EVP_PKEY_free(pkey);
    }
    // --- BEGIN OPENSSL HACK ---
    NSData *rawDataValue = [NSData dataWithBytesNoCopy:publicBytes length:publicBytesLength];
    NSMutableString *dataString = [[NSMutableString alloc] initWithData:rawDataValue encoding:NSUTF8StringEncoding];
    // Remove: '-----BEGIN RSA PUBLIC KEY-----' or '-----END RSA PUBLIC KEY-----'
    NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:@"(-{5,}BEGIN (RSA )?PUBLIC KEY-{5,})|(-{5,}END (RSA )?PUBLIC KEY-{5,})|\n" options:0 error:nil];
    [regex replaceMatchesInString:dataString options:0 range:NSMakeRange(0, dataString.length) withTemplate:@""];
    // --- END OPENSSL HACK ---
    return [[NSData alloc] initWithBase64EncodedString:dataString options:NSDataBase64DecodingIgnoreUnknownCharacters];
}

- (NSData *)encryptWithPKCS1Padding:(NSData *)messageData error:(NSError **)error {
    NSMutableData *cipherData = [NSMutableData dataWithLength:(NSUInteger)RSA_size(self.rsa)];
    int cipherBytesLenght = RSA_public_encrypt((int)messageData.length, messageData.bytes, cipherData.mutableBytes, self.rsa, RSA_PKCS1_PADDING);
    if (cipherBytesLenght < 0) {
        if (error) {
            *error = [NSError errorWithDomain:@"OpenSSL Error" code:-1 userInfo:@{}];
        }
    }
    [cipherData setLength:(NSUInteger)cipherBytesLenght];
    return cipherData;
}

- (BOOL)verifySignatureWithSHA256:(NSData *)signature message:(NSData *)message {
    SHA256_CTX sha256Ctx;
    unsigned char messageDigest[SHA256_DIGEST_LENGTH];
    if(!SHA256_Init(&sha256Ctx)) {
        return NO;
    }
    if (!SHA256_Update(&sha256Ctx, message.bytes, message.length)) {
        return NO;
    }
    if (!SHA256_Final(messageDigest, &sha256Ctx)) {
        return NO;
    }
    if (RSA_verify(NID_sha256, messageDigest, SHA256_DIGEST_LENGTH, signature.bytes, (int)signature.length, self.rsa) == 0) {
        return NO;
    }
    return YES;
}

@end
