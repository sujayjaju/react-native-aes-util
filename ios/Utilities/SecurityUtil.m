//
//  SecurityUtil.m
//  RNAncoriaUtil
//
//  Created by Savvas Koualis on 24/01/2019.
//  Copyright © 2019 Facebook. All rights reserved.
//

#import <Foundation/Foundation.h>

#import "GTMBase64.h"
#import "SecRandom.h"
#import "IAGAesGcm.h"
#import "SecurityUtil.h"



@implementation SecurityUtil

#pragma mark - AES

+(NSString*)encryptAES:(NSString*)string key:(NSString*)key aad:(NSString *)aad
{

    // SK: encode plain text
    NSData *plainTextData = [string dataUsingEncoding:NSUTF8StringEncoding];
    // SK: decode secret key from base64
    NSData *secretKeyData = [GTMBase64 decodeString:key];
    // SK: encode additional authenticated data
    NSData *aadData = [aad dataUsingEncoding:NSUTF8StringEncoding];
    
    int err = 0;
    NSMutableData* ivMutableData = [NSMutableData dataWithLength:16];
    err = SecRandomCopyBytes(kSecRandomDefault, 16, [ivMutableData mutableBytes]);
    
    NSData* ivData = [NSData dataWithData:ivMutableData];
    
    IAGCipheredData* cipheredData = [IAGAesGcm cipheredDataByAuthenticatedEncryptingPlainData:plainTextData
                                    withAdditionalAuthenticatedData:aadData
                                    authenticationTagLength:IAGAuthenticationTagLength128
                                    initializationVector:ivData
                                    key:secretKeyData
                                    error:nil];

    
    NSMutableData *ivAndCipherData = [NSMutableData dataWithData:ivData];

    [ivAndCipherData appendBytes:cipheredData.cipheredBuffer length:cipheredData.cipheredBufferLength];
    [ivAndCipherData appendBytes:cipheredData.authenticationTag length:cipheredData.authenticationTagLength];
    
    NSData *resultData = [NSData dataWithData:ivAndCipherData];
    
    NSString *result = [resultData base64EncodedStringWithOptions:0];
    return result;
}


+(NSString*)decryptAES:(NSString *)string key:(NSString *)key aad:(NSString *)aad
{
    // SK: decode encrypted data from base64 data
    NSData *encryptedData = [GTMBase64 decodeString:string];
    // SK: extract IV bytes
    NSData *ivData = [encryptedData subdataWithRange:NSMakeRange(0, 16)];
    // SK: extract ciphertext data
    NSData *cipherData = [encryptedData subdataWithRange:NSMakeRange(ivData.length, encryptedData.length - (ivData.length + IAGAuthenticationTagLength128))];
    // SK: extract authentication tag data
    NSData *authTagData = [encryptedData subdataWithRange:NSMakeRange(encryptedData.length - 16, IAGAuthenticationTagLength128)];
    // SK: decode secret key from base64
    NSData *secretKeyData = [GTMBase64 decodeString:key];
    // SK: encode additional authenticated data
    NSData *aadData = [aad dataUsingEncoding:NSUTF8StringEncoding];
    
   

    IAGCipheredData *AGCipherData = [[IAGCipheredData alloc] initWithCipheredBuffer:cipherData.bytes
                                                                 cipheredBufferLength:cipherData.length
                                                                    authenticationTag:authTagData.bytes
                                                              authenticationTagLength:authTagData.length];
    
    NSData *plainData = [IAGAesGcm plainDataByAuthenticatedDecryptingCipheredData:AGCipherData
                                                               withAdditionalAuthenticatedData:aadData
                                                                          initializationVector:ivData
                                                                                           key:secretKeyData
                                                                                         error:nil];
    NSString *resultString = [[NSString alloc] initWithData:plainData encoding:NSUTF8StringEncoding];
    
    return resultString;
}

@end
