//
//  CryptoUtil.m
//  ChoreTracker_Adult
//
//  Created by Tik on 8/12/2015.
//  Copyright © 2015 Moroku. All rights reserved.
//

#import "CryptoUtil.h"
#import "Constants.h"
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>


// JSON key strings
NSString * const kUtcDate = @"utc_date";
NSString * const kBase64Md5Content = @"base64_md5_content";
NSString * const kHmacSha1 = @"hmac_sha1";

// Http keys
NSString * const kHttpContentLength = @"Content-Length";
NSString * const kHttpContentType = @"Content-Type";
NSString * const kHttpAccept = @"Accept";
NSString * const kHttpAuthorization = @"Authorization";
NSString * const kHttpContentMd5 = @"Content-MD5";
NSString * const kHttpDate = @"Date";



@implementation CryptoUtil

- (NSData *)doAES:(NSData *)dataIn context:(CCOperation)kCCEncrypt_or_kCCDecrypt key:(NSData *)key
          options:(CCOptions)options iv:(NSData *)iv error:(NSError **)error
{
    CCCryptorStatus ccStatus   = kCCSuccess;
    size_t          cryptBytes = 0;
    NSMutableData  *dataOut    = [NSMutableData dataWithLength:dataIn.length + kCCBlockSizeAES128];
    
    ccStatus = CCCrypt( kCCEncrypt_or_kCCDecrypt,
                       kCCAlgorithmAES,
                       options,
                       key.bytes,
                       key.length,
                       (iv)?nil:iv.bytes,
                       dataIn.bytes,
                       dataIn.length,
                       dataOut.mutableBytes,
                       dataOut.length,
                       &cryptBytes);
    
    if (ccStatus == kCCSuccess) {
        dataOut.length = cryptBytes;
    }
    else {
        if (error) {
            *error = [NSError errorWithDomain:@"kEncryptionError"
                                         code:ccStatus
                                     userInfo:nil];
        }
        dataOut = nil;
    }
    
    return dataOut;
}

-(NSString *)EncryptAES:(NSString *)text secretKey:(NSString *)key {
    NSString *encryptedStr = @"";
    if (!text || !key) {
        return encryptedStr;
    }
    if( (text.length == 0 )|| (key.length == 0) ) {
        return encryptedStr;
    }
    
    NSError *error;
    NSMutableData *keyData = [NSMutableData dataWithLength:kCCKeySizeAES128];
    NSData *dataOriginal = [text dataUsingEncoding:NSUTF8StringEncoding];;
    
    NSData *dataEncrypted = [self doAES:dataOriginal
                                context:kCCEncrypt
                                    key:keyData
                                options:kCCOptionPKCS7Padding | kCCOptionECBMode
                                     iv:nil
                                  error:&error];
    if (dataEncrypted) {
        encryptedStr = [dataEncrypted base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    }
    return encryptedStr;
}

-(NSString *)DecryptAES:(NSString *)base64Text secretKey:(NSString *)key {
    NSString *decryptedStr = @"";
    if (!base64Text || !key) {
        return decryptedStr;
    }
    if( (base64Text.length == 0 )|| (key.length == 0) ) {
        return decryptedStr;
    }
    
    NSError *error;
    NSMutableData *keyData = [NSMutableData dataWithLength:kCCKeySizeAES128];
    NSData *dataToDecrypt = [[NSData alloc] initWithBase64EncodedString:base64Text options:NSDataBase64DecodingIgnoreUnknownCharacters];
    
    NSData *dataDecrypted = [self doAES:dataToDecrypt
                                context:kCCDecrypt
                                    key:keyData
                                options:kCCOptionPKCS7Padding | kCCOptionECBMode
                                     iv:nil
                                  error:&error];
    
    if (dataDecrypted) {
        decryptedStr = [[NSString alloc] initWithData:dataDecrypted encoding:NSUTF8StringEncoding];
    }
    return decryptedStr;
}

- (NSString *)MD5_EncodeBase64:(NSString *)text {
    const char *ch = [text UTF8String];
    unsigned char md5Buffer[CC_MD5_DIGEST_LENGTH];
    
    CC_MD5(ch, (CC_LONG)strlen(ch), md5Buffer);
    
    // Don't do strlen(md5Buffer), the buffer can contain NULL
    // strlen counts up until NULL is found
    NSData *data = [NSData dataWithBytes:md5Buffer length:CC_MD5_DIGEST_LENGTH];
    return [data base64EncodedStringWithOptions:0];
}

- (NSString *)HMAC_SHA1:(NSString *)text secretKey:(NSString *)secret {
    
    NSString *hmac = @"";
    
    NSData* secretData = [secret dataUsingEncoding:NSUTF8StringEncoding];
    NSData *textData = [text dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableData *hmacData = [NSMutableData dataWithLength:CC_SHA1_DIGEST_LENGTH];
    
    CCHmac(kCCHmacAlgSHA1, secretData.bytes, secretData.length, textData.bytes, textData.length, hmacData.mutableBytes);
    
    // Sample signatureData <dd26bfdd f122c105 5d4cd5b0 54227727 e1e3eecf>
    // We want dd26bfddf122c1055d4cd5b054227727e1e3eecf
    hmac = [[hmacData description] stringByReplacingOccurrencesOfString:@" " withString:@""];
    hmac = [hmac stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"<>"]];
    
    return hmac;
}



/**
 * Construct HMAC from request and payload
 */
- (NSDictionary *)HMAC_SHA1_WithContent:(NSString *)content
                              localDate:(NSDate *)date
                           resourcePath:(NSString *)apiPath
                             httpMethod:(NSString *)httpMethod
                              secretKey:(NSString *)secret {
    
    NSDictionary *resultDict = nil;
    if(!date || ((id)date == [NSNull null]) ) {
        date = [NSDate date];
    }
    if( (content && apiPath && httpMethod && secret)
       && ((id)content != [NSNull null])
       && ((id)apiPath != [NSNull null])
       && ((id)httpMethod != [NSNull null])
       && ((id)secret != [NSNull null])
       ) {
        content = [content stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        NSString *base64Content = [self MD5_EncodeBase64:content];
        
        NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
        [dateFormatter setDateFormat:@"yyyyMMdd HH:mm:ss"];
        [dateFormatter setTimeZone:[NSTimeZone timeZoneWithAbbreviation:@"UTC"]];
        NSString *utcDate = [NSString stringWithFormat:@"%@ UTC", [dateFormatter stringFromDate:date]];
        
        // Need to escape the newline character with a blackslash
        NSString *rawText = [NSString stringWithFormat:@"%@\\n%@\\n%@\\n%@", utcDate, base64Content, apiPath, [httpMethod uppercaseString]];
        NSString *hmac = [self HMAC_SHA1:rawText secretKey:secret];
        
        resultDict = [NSDictionary dictionaryWithObjectsAndKeys:
                      base64Content, kBase64Md5Content,
                      utcDate, kUtcDate,
                      hmac, kHmacSha1,
                      nil
                      ];
    }
    return resultDict;
}


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
                                 secretKey:(NSString *)secret {
    
    NSDictionary *resultDict = nil;
    
    // Date to use
    NSDate *date = [NSDate date];
    
    if( content && apiPath.length > 0 && httpMethod.length > 0 && secret.length > 0 ) {
        NSString *base64Content = [self base64EncodedMD5Hash:content];
        NSString *utcDate = [self dateToUTCString:date];
        
        // Need to escape the newline character with a blackslash
        NSString *plainText = [NSString stringWithFormat:@"%@\\n%@\\n%@\\n%@", utcDate, base64Content, apiPath, [httpMethod uppercaseString]];
        NSString *hmac = [self HMAC_SHA1:plainText secretKey:secret];
        
        resultDict = @{kBase64Md5Content : base64Content,
                       kUtcDate          : utcDate,
                       kHmacSha1         : hmac};
    } else {
        DDLogError( @"Invalid parameter in request to HMAC_SHA1_WithContent:resourcePath:httpMethod:secretKey:");
    }
    return resultDict;
}


/**
 * @param The input date
 * @return an NSSTring representtion of the NSDate in the form yyyyMMdd HH:mm:ss
 */
-(NSString *) dateToUTCString:(NSDate *) date {
    NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
    [dateFormatter setDateFormat:@"yyyyMMdd HH:mm:ss"];
    [dateFormatter setTimeZone:[NSTimeZone timeZoneWithAbbreviation:@"UTC"]];
    NSString *utcDate = [NSString stringWithFormat:@"%@ UTC", [dateFormatter stringFromDate:date]];
    return utcDate;
}


/**
 * Perform MD5 hash of NSData and then B64 encode it
 * @param data The data to be hashed
 */
- (NSString *)base64EncodedMD5Hash:(NSData *) plainText {
    unsigned char md5Buffer[CC_MD5_DIGEST_LENGTH];
    
    CC_MD5(plainText.bytes, (CC_LONG)plainText.length, md5Buffer);
    
    NSData *hash = [NSData dataWithBytes:md5Buffer length:CC_MD5_DIGEST_LENGTH];
    return [hash base64EncodedStringWithOptions:0];
}

/**
 * Perform SHA1 hash of NSString and then B64 encode it
 * @param plainText to be hashed
 */
- (NSString *)base64EncodedSHA1Hash:(NSString *)plainText {
    
    NSData *data = [plainText dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char sha1Buffer[CC_SHA1_DIGEST_LENGTH];
    
    CC_SHA1(data.bytes, (CC_LONG)data.length, sha1Buffer);
    
    NSData *hash = [NSData dataWithBytes:sha1Buffer length:CC_SHA1_DIGEST_LENGTH];
    return [hash base64EncodedStringWithOptions:0];
}

@end