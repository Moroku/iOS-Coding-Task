//
//  CryptoUtil.h
//  ChoreTracker_Adult
//
//  Created by Tik on 8/12/2015.
//  Copyright © 2015 Moroku. All rights reserved.
//

#ifndef _CryptoUtil_h_
#define _CryptoUtil_h_

// JSON key strings
extern NSString * const kUtcDate;
extern NSString * const kBase64Md5Content;
extern NSString * const kHmacSha1;

// Http keys
extern NSString * const kHttpContentLength;
extern NSString * const kHttpContentType;
extern NSString * const kHttpAccept;
extern NSString * const kHttpAuthorization;
extern NSString * const kHttpContentMd5;
extern NSString * const kHttpDate;

#import <Foundation/Foundation.h>

@interface CryptoUtil : NSObject

-(NSString *)base64EncodedSHA1Hash:(NSString *)plainText;
-(NSString *)base64EncodedSHA256Hash:(NSString *)plainText;

-(NSString *)EncryptAES:(NSString *)text secretKey:(NSString *)key;
-(NSString *)DecryptAES:(NSString *)base64Text secretKey:(NSString *)key;

-(NSDictionary *)HMAC_SHA1_WithContent:(NSString *)content localDate:(NSDate *)date resourcePath:(NSString *)apiPath httpMethod:(NSString *)httpMethod secretKey:(NSString *)secret;


/**
 * Construct HMAC from request and NSData payload
 * @param content NSData object representing the content of the HTTP request. This is the output of JSONSeriializer
 * @param resourcePath the path of the URL request
 * @param httpMethod (GET, PUT, POST, DELETE)
 * @param secretKey the key to use to perfrom the hashing
 * @return an NSDictionary with the following keys :kBase64Md5Content, kHmacSha1kUtcDate
 */
- (NSDictionary *) generateHMACWithContent:(NSData *)content
                              resourcePath:(NSString *)apiPath
                                httpMethod:(NSString *)httpMethod
                                 secretKey:(NSString *)secret;

@end

#endif //_CryptoUtil_h_