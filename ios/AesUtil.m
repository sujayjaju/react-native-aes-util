#import "AesUtil.h"


@implementation AesUtil

RCT_EXPORT_MODULE()

RCT_EXPORT_METHOD(sampleMethod:(NSString *)stringArgument numberParameter:(nonnull NSNumber *)numberArgument callback:(RCTResponseSenderBlock)callback)
{
    // TODO: Implement some actually useful functionality
    callback(@[[NSString stringWithFormat: @"numberArgument: %@ stringArgument: %@", numberArgument, stringArgument]]);
}


RCT_EXPORT_METHOD(encrypt:(NSString *)string
                  key:(NSString *)key
                  aad:(NSString *)aad
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
    NSString *encryptedString = [SecurityUtil encryptAES:string key:key aad:aad];
    if (encryptedString.length <= 0) {
        reject(@"ERROR", @"encrypt failed", nil);
    }
    resolve (encryptedString);
}

RCT_EXPORT_METHOD(decrypt:(NSString *)string
                  key:(NSString *)key
                  aad:(NSString *)aad
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
    NSString *decryptedString = [SecurityUtil decryptAES:string key:key aad:aad];
    
    if (decryptedString.length <= 0) {
        reject(@"ERROR", @"decrypt failed", nil);
    }
    resolve (decryptedString);
}

RCT_EXPORT_METHOD(signJwt:(NSString *)jwt
                  key:(NSString *)key
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
    NSError *jsonError;
    NSDictionary *payload = [Jwt decodeWithToken:jwt andKey:nil andVerify:false andError:&jsonError];
    NSString *hashedKey = [Jwt sha256:key];
    NSError *error;
	NSString *token = [Jwt encodeWithPayload:payload andKey:hashedKey andError:&error];
    
	if(token == nil) {
		// Print error
        NSLog(@"Code: %li", (long)[error code]);
		NSLog(@"Reason: %@", [error localizedFailureReason]);
        reject(@"ERROR", @"jwt sign failed", nil);
    }
	
    resolve (token);
}

RCT_EXPORT_METHOD(decodeJwt:(NSString *)string
                  key:(NSString *)key
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
    NSNumber *num = [NSNumber numberWithInt:0];
    BOOL *verify = [num boolValue];

	if([key length] > 0)
	{
        num = [NSNumber numberWithInt:1];
        verify = [num boolValue];
	}
	
	NSError *error;
    NSDictionary *decoded = [Jwt decodeWithToken:string andKey:key andVerify:verify andError:&error];
	
	if(decoded == nil) {
		// Print error
        NSLog(@"Code: %li", (long)[error code]);
		NSLog(@"Reason: %@", [error localizedFailureReason]);
		reject(@"ERROR", @"decode jwt failed", nil);
	}
	
	NSData *jsonData = [NSJSONSerialization dataWithJSONObject:decoded 
                                                   options:0
                                                     error:nil];
    resolve ([[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding]);
}
@end
