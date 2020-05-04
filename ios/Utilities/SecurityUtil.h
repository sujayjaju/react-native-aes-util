//
//  SecurityUtil.h
//  RNAncoriaUtil
//
//  Created by Savvas Koualis on 24/01/2019.
//  Copyright © 2019 Facebook. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface SecurityUtil : NSObject

#pragma mark - AES加密

// SK: encrypt string using AES GCM 256
+ (NSString*)encryptAES:(NSString*)string key:(NSString*)key aad:(NSString *)aad;


// SK: decrypt string using AES GCM 256
+ (NSString*)decryptAES:(NSString *)string key:(NSString *)key aad:(NSString *)aad;

@end
