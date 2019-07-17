//
//  MCRSAUtils.m
//  RSAKey
//
//  Created by MingleChang on 2019/7/17.
//  Copyright © 2019 MingleChang. All rights reserved.
//

#import "MCRSAUtils.h"
#import "MCRSAPublicKey.h"
#import "MCRSAPrivateKey.h"
@implementation MCRSAUtils
+ (void)createKeyWithPublicKey:(MCRSAPublicKey **)publicKey privateKey:(MCRSAPrivateKey **)privateKey {
    BIGNUM *exponent = BN_new();
    BN_set_word(exponent, RSA_F4);
    @try {
        RSA *rsa = RSA_new();
        if (!RSA_generate_key_ex(rsa, 256 * 8, exponent, NULL)) {
            NSAssert(NO, nil);
        }
        *publicKey = [[MCRSAPublicKey alloc] initWithRSA:rsa];
        *privateKey = [[MCRSAPrivateKey alloc] initWithRSA:rsa];
        
        RSA_free(rsa);
    }
    @finally {
        BN_free(exponent);
    }
}
@end
