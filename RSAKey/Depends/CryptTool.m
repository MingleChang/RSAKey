//
//  cryptTool.m
//  welfareAssociation
//
//  Created by yang li on 2019/1/14.
//  Copyright © 2019 GoodSoGood. All rights reserved.
//

#import "CryptTool.h"
#import "rc4obj.h"
#import "NSData+Encryption.h"

#define data1 @"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxbmFo8hZ3EUktF6Tb9r+zKBtIm8miGK"
#define data2 @"qgd2jzJRmtwyecqcKvdhtij67azn7CxCylhbO/JGTuH50+sH6+bQdj4mnY9NS9QjZg"
#define data3 @"n5dsYxss38Jmnil9CHi7gaox4LkxPYNyt8xX0bLvXNRVxWS+t+W8DfQZcwxFq6lYbE"
#define data4 @"uy7/TInRSvC+PK1SDo67QonDatqJcHpv42W1Yc+4BbbiWnNQFl6CW4HWoKN89ANvQMnwv0/cy3Ayis"
#define data5 @"PHtcCIIcJdbhZjvPeafvtuYj/Wd+TctlIan7cPXWt587hcChbbEtozlAKvUdYkjosHaf0UwTw3mnPvzx+ZDUJhKxj5LkPaugT7OdwIDAQAB"

#define data10 @"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkPrF0zjwxQyYUl8CwX1FthSwUW"
#define data11 @"QIP+j8zJ0iMvcNNM/2AcT1b6xHRh8Eq+G8yhM1dWMXgkSGOxhaV/Q56t0BAgMOBbqlp/36+G333cTW1txzjNv"
#define data12 @"IQC05cTN0HSb11GH4s24CGZKFPNlSgGeZAiGYA/fjxxCgoe18cUj2I3cyjyay5rwq4c//SANWzPI8h/cu"
#define data13 @"O4EhEM4UDNlh5XLlgVzrjauRLCXvPP0PWxJCD2CaPvDvXzkXaPS"
#define data14 @"zdNhWO6TYXBACeGvqrOvKCo7uAcKu7+t8bPUI6gBD/m7NEPCrf9EZ3VpfktCKbTFhxtf0Gpq7xCIPmaAUkfTrmQLa1ofh2zLCewIDAQAB"

static const NSString *PrivateKeyIdentifier = @"com.goodsogood.GSPay.private";
static const NSString *PublicKeyIdentifier = @"com.goodsogood.GSPay.public";

@interface CryptPublicSecKey ()

@property (nonatomic, assign) RSA *rsa;

@end

@implementation CryptPublicSecKey

NSString *const OpenSSLErrorDomain = @"OpenSSLErrorDomain";

- (instancetype)initWithRSA:(RSA *)rsa {
    if (self = [super init]) {
        CRYPTO_add(&rsa->references, 1, CRYPTO_LOCK_RSA);
        self.rsa = rsa;
    }
    return self;
}

- (instancetype)initWithData:(NSData *)dataValue {
    NSParameterAssert([dataValue isKindOfClass:[NSData class]]);
    self = [super init];
    if (self) {
        NSString *base64DataString = [dataValue base64EncodedStringWithWrapWidth:64];
        base64DataString = [@"-----BEGIN PUBLIC KEY-----\n" stringByAppendingString:base64DataString];
        base64DataString = [base64DataString stringByAppendingString:@"\n-----END PUBLIC KEY-----"];
        NSData *base64Data = [base64DataString dataUsingEncoding:NSUTF8StringEncoding];
        
        BIO *publicBIO = BIO_new_mem_buf((void *)base64Data.bytes, (int)base64Data.length);
        EVP_PKEY *pkey = EVP_PKEY_new();
        @try {
            if (!PEM_read_bio_PUBKEY(publicBIO, &pkey, NULL, NULL)) {
                NSAssert(NO, nil);
            }
            self.rsa = EVP_PKEY_get1_RSA(pkey);
        }
        @finally{}
        
    }
    return self;
}

- (NSData *)dataValue {
    // OpenSSL PEM Writer requires the key in EVP_PKEY format:
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
    NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:@"(-{5,}BEGIN (RSA )?PUBLIC KEY-{5,})|(-{5,}END (RSA )?PUBLIC KEY-{5,})|\n"
                                                                           options:0
                                                                             error:nil];
    [regex replaceMatchesInString:dataString
                          options:0
                            range:NSMakeRange(0, dataString.length)
                     withTemplate:@""];
    // --- END OPENSSL HACK ---
    
    return [[NSData alloc] initWithBase64EncodedString:dataString options:NSDataBase64DecodingIgnoreUnknownCharacters];
}

- (NSData *)encrypt:(NSData *)messageData error:(NSError **)error {
    NSMutableData *cipherData = [NSMutableData dataWithLength:(NSUInteger)RSA_size(self.rsa)];
    int cipherBytesLenght = RSA_public_encrypt((int)messageData.length, messageData.bytes, cipherData.mutableBytes, self.rsa, 1);
    if (cipherBytesLenght < 0) {
        if (error) { *error = [NSError errorWithDomain:OpenSSLErrorDomain code:-1 userInfo:@{}]; }
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

@interface CryptPrivateSecKey ()

@property (nonatomic, assign) RSA *rsa;

@end

@implementation CryptPrivateSecKey

- (instancetype)initWithRSA:(RSA *)rsa {
    if (self = [super init]) {
        CRYPTO_add(&rsa->references, 1, CRYPTO_LOCK_RSA);
        self.rsa = rsa;
    }
    return self;
}

- (instancetype)initWithData:(NSData *)dataValue {
    NSParameterAssert([dataValue isKindOfClass:[NSData class]]);
    self = [super init];
    if (self) {
        
        // --- BEGIN OPENSSL HACK ---
        NSString *base64DataString = [dataValue base64EncodedStringWithWrapWidth:64];
        base64DataString = [@"-----BEGIN RSA PRIVATE KEY-----\n" stringByAppendingString:base64DataString];
        base64DataString = [base64DataString stringByAppendingString:@"\n-----END RSA PRIVATE KEY-----"];
        NSData *base64Data = [base64DataString dataUsingEncoding:NSUTF8StringEncoding];
        // --- END OPENSSL HACK ---
        
        BIO *privateBIO = BIO_new_mem_buf((void *) base64Data.bytes, (int)base64Data.length);
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
    
    NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:@"(-{5,}BEGIN (RSA )?PRIVATE KEY-{5,})|(-{5,}END (RSA )?PRIVATE KEY-{5,})|\n"
                                                                           options:0
                                                                             error:nil];
    [regex replaceMatchesInString:dataString
                          options:0
                            range:NSMakeRange(0, dataString.length)
                     withTemplate:@""];
    
    return [[NSData alloc] initWithBase64EncodedString:dataString options:NSDataBase64DecodingIgnoreUnknownCharacters];
}

- (NSData *)decrypt:(NSData *)cipherData error:(NSError **)error {
    NSUInteger rsaSize = (NSUInteger) RSA_size(self.rsa);
    NSMutableData *messageData = [NSMutableData dataWithLength:rsaSize];
    int messageBytesLength = RSA_private_decrypt((int)cipherData.length, cipherData.bytes, messageData.mutableBytes, self.rsa, 1);
    if (messageBytesLength < 0) {
        if (error) { *error = [NSError errorWithDomain:OpenSSLErrorDomain code:-1 userInfo:@{}]; }
        return nil;
    }
    [messageData setLength:(NSUInteger) messageBytesLength];
    
    return messageData;
}

- (NSData *)signWithSHA256:(NSData *)message error:(NSError **)error {
    SHA256_CTX sha256Ctx;
    unsigned char messageDigest[SHA256_DIGEST_LENGTH];
    if (!SHA256_Init(&sha256Ctx)) {
        if (error) *error = [NSError errorWithDomain:OpenSSLErrorDomain code:-1 userInfo:@{}];
        return nil;
    }
    if (!SHA256_Update(&sha256Ctx, message.bytes, message.length)) {
        if (error) *error = [NSError errorWithDomain:OpenSSLErrorDomain code:-1 userInfo:@{}];
        return nil;
    }
    if (!SHA256_Final(messageDigest, &sha256Ctx)) {
        if (error) *error = [NSError errorWithDomain:OpenSSLErrorDomain code:-1 userInfo:@{}];
        return nil;
    }
    
    NSMutableData *signature = [NSMutableData dataWithLength:(NSUInteger) RSA_size(_rsa)];
    unsigned int signatureLength = 0;
    if (RSA_sign(NID_sha256, messageDigest, SHA256_DIGEST_LENGTH, signature.mutableBytes, &signatureLength, _rsa) == 0) {
        if (error)
            *error = [NSError errorWithDomain:OpenSSLErrorDomain code:-1 userInfo:@{}];
        return nil;
    }
    [signature setLength:(NSUInteger) signatureLength];
    
    return signature;
}

@end

@implementation CryptTool

+ (CryptPublicSecKey *)getKey {
//    NSString *base64String = [self appendStringWithArray:@[data1, data2, data3, data4, data5]];
    NSString *base64String = [self appendStringWithArray:@[data10, data11, data12, data13, data14]];
    return [self publicSecKeyFromKeyString:base64String];
}

+ (void)createKeyWithPublicKey:(CryptPublicSecKey **)publicKey privateKey:(CryptPrivateSecKey **)privateKey {
    
    BIGNUM *exponent = BN_new();
    BN_set_word(exponent, 65537);
    @try {
        RSA *rsa = RSA_new();
        if (!RSA_generate_key_ex(rsa, 256 * 8, exponent, NULL)) {
            NSAssert(NO, nil);
        }
        
        *publicKey = [[CryptPublicSecKey alloc] initWithRSA:rsa];
        *privateKey = [[CryptPrivateSecKey alloc] initWithRSA:rsa];
        
        RSA_free(rsa);
    }
    @finally {
        BN_free(exponent);
    }
    
}


#pragma mark - CryptPublicSecKey
+ (NSData *)getPublicKeyBitsFromPublicKey:(CryptPublicSecKey *)publicKey {
    return [publicKey dataValue];
}

+ (NSString *)getPublicKeyBase64StringFromPublicKey:(CryptPublicSecKey *)publicKey {
    return [[publicKey dataValue] base64EncodedString];
}

+ (CryptPublicSecKey *)publicSecKeyFromKeyString:(NSString *)givenString {
    return [self publicSecKeyFromKeyBits:[[NSData alloc] initWithBase64EncodedString:givenString options:NSDataBase64DecodingIgnoreUnknownCharacters]];
}

+ (CryptPublicSecKey *)publicSecKeyFromKeyBits:(NSData *)givenData {
    return [[CryptPublicSecKey alloc] initWithData:givenData];;
}

+ (NSData *)encryptWithPublicKey:(CryptPublicSecKey *)publicKey string:(NSString *)plainString {
    return [self encryptWithPublicKey:publicKey Data:[plainString dataUsingEncoding:NSUTF8StringEncoding]];
}

+ (NSData *)encryptWithPublicKey:(CryptPublicSecKey *)publicKey Data:(NSData *)plainData {
    
    NSError *error;
    NSData *cipherText = [publicKey encrypt:plainData error:&error];
    NSAssert(cipherText && !error, nil);
    
    return cipherText;
    
}


#pragma mark - CryptPrivateSecKey

+ (NSData *)getPrivateKeyBitsFromPrivateKey:(CryptPrivateSecKey *)privateKey {
    return [privateKey dataValue];
}

+ (NSString *)getPrivateKeyBase64StringFromPrivateKey:(CryptPrivateSecKey *)privateKey {
    return [[self getPrivateKeyBitsFromPrivateKey:privateKey] base64EncodedString];
}

+ (CryptPrivateSecKey *)privateSecKeyFromKeyString:(NSString *)givenString {
    return [self privateSecKeyFromKeyBits:[[NSData alloc] initWithBase64EncodedString:givenString options:NSDataBase64DecodingIgnoreUnknownCharacters]];
}

+ (CryptPrivateSecKey *)privateSecKeyFromKeyBits:(NSData *)givenData {
    return [[CryptPrivateSecKey alloc] initWithData:givenData];
}

+ (BOOL)verifyWithPublicKey:(CryptPublicSecKey *)publicKey SignedData:(NSData *)signedData Signature:(NSData *)signature {
    return [publicKey verifySignatureWithSHA256:signature message:signedData];
}

+ (NSData *)decryptWithPrivateKey:(CryptPrivateSecKey *)privateKey Data:(NSData *)cipherData {
    
    NSError *error;
    NSData *clearData = [privateKey decrypt:cipherData error:&error];
    NSAssert(clearData && !error, nil);
    
    return clearData;
    
}

+ (NSData *)signWithPrivateKey:(CryptPrivateSecKey *)privateKey Data:(NSData *)data {
    
    NSError *error;
    NSData *signData = [privateKey signWithSHA256:data error:&error];
    NSAssert(signData && !error, nil);
    
    return signData;
    
}


#pragma mark - rc4加解密
+ (NSData *)rc4EncryptWithKey:(NSString *)key String:(NSString *)string {
    return [self rc4EncryptWithKey:key Data:[string dataUsingEncoding:NSUTF8StringEncoding]];
}

+ (NSData *)rc4EncryptWithKey:(NSString *)key Data:(NSData *)data {
    const char *keyData = [[key dataUsingEncoding:NSUTF8StringEncoding] bytes];

    int datalen = (int)data.length;
    char *encryptByte = rc4encrypt((char *)keyData, (int)key.length, (char *)data.bytes, datalen);

    NSData *encryptData = [NSData dataWithBytes:encryptByte length:datalen];
    rc4freedata(encryptByte);
    return encryptData;
}

+ (NSData *)rc4DecryptWithKey:(NSString *)key Data:(NSData *)data {
    const char *keyByte = [key cStringUsingEncoding:NSUTF8StringEncoding];
    char *clearByte = rc4decrypt((char *)keyByte, (int)key.length, (char *)data.bytes, (int)data.length);
    NSData *clearData = nil;
    if (clearByte) {
        clearData = [NSData dataWithBytes:clearByte length:data.length];
    }
    return clearData;
}

+ (NSData *)convertHexStrToData:(NSString *)str {
    if (!str || [str length] == 0) {
        return nil;
    }
    
    NSMutableData *hexData = [[NSMutableData alloc] initWithCapacity:20];
    NSRange range;
    if ([str length] % 2 == 0) {
        range = NSMakeRange(0, 2);
    } else {
        range = NSMakeRange(0, 1);
    }
    for (NSInteger i = range.location; i < [str length]; i += 2) {
        unsigned int anInt;
        NSString *hexCharStr = [str substringWithRange:range];
        NSScanner *scanner = [[NSScanner alloc] initWithString:hexCharStr];
        
        [scanner scanHexInt:&anInt];
        NSData *entity = [[NSData alloc] initWithBytes:&anInt length:1];
        [hexData appendData:entity];
        
        range.location += range.length;
        range.length = 2;
    }
    return hexData;
}

#pragma mark - Private
+ (NSString *)appendStringWithArray:(NSArray *)array {
    NSMutableString *string = [NSMutableString string];
    for (NSString *subString in array) {
        [string appendString:subString];
    }
    return string;
}

@end
