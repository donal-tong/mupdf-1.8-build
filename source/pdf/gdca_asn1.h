/*
* Copyright (c) 2004, 
* All rights reserved.
* 
* 文件名称：gdca_asn1.h
* 
* 当前版本：1.0
* 作    者：
* 完成日期：2004年5月30日
* 主要修改说明：
*
* 历史信息：
*
* 版本：
* 作者：
* 日期：
* 主要修改说明：
*
* 版本：
* 作者：
* 日期：
* 主要修改说明：
*
*/

#ifndef _GDCA_ASN1_
#define _GDCA_ASN1_

#ifdef __cplusplus
extern "C" {
#endif

#define GDCA_ASN1_METHOD_MASK		           0x20
#define GDCA_ASN1_PRIMITIVE		               0x00
#define GDCA_ASN1_CONSTRUCTED		           0x20

#define GDCA_ASN1_CLASS_MASK		           0xc0
#define GDCA_ASN1_UNIVERSAL		               0x00
#define GDCA_ASN1_APPLICATION		           0x40
#define GDCA_ASN1_CONTEXT_SPECIFIC	           0x80
#define GDCA_ASN1_PRIVATE	        	       0xc0

#define GDCA_ASN1_LOW_TAG_MASK		           0x1f

#define GDCA_ASN1_BOOLEAN		               0x01
#define GDCA_ASN1_INTEGER		               0x02
#define GDCA_ASN1_BIT_STRING		           0x03
#define GDCA_ASN1_OCTET_STRING		           0x04
#define GDCA_ASN1_NULL			               0x05
#define GDCA_ASN1_OBJECT_ID		               0x06
#define GDCA_ASN1_OBJECT_DESCRIPTOR            0x07
#define GDCA_ASN1_REAL                         0x09
#define GDCA_ASN1_ENUMERATED		           0x0a
#define GDCA_ASN1_EMBEDDED_PDV                 0x0b
#define GDCA_ASN1_UTF8_STRING		           0x0c
#define GDCA_ASN1_SEQUENCE		               0x10
#define GDCA_ASN1_SET			               0x11
#define GDCA_ASN1_NUMERIC_STRING               0x12
#define GDCA_ASN1_PRINTABLE_STRING	           0x13
#define GDCA_ASN1_T61_STRING		           0x14
#define GDCA_ASN1_TELETEX_STRING               GDCA_ASN1_T61_STRING
#define GDCA_ASN1_VIDEOTEX_STRING              0x15
#define GDCA_ASN1_IA5_STRING		           0x16
#define GDCA_ASN1_UTC_TIME		               0x17
#define GDCA_ASN1_GENERALIZED_TIME	           0x18
#define GDCA_ASN1_GRAPHIC_STRING               0x19
#define GDCA_ASN1_VISIBLE_STRING		       0x1a
#define GDCA_ASN1_GENERAL_STRING               0x1b
#define GDCA_ASN1_UNIVERSAL_STRING	           0x1c
#define GDCA_ASN1_BMP_STRING		           0x1e


#define GDCA_ASN1_OPTIONAL	                   0x000100
#define GDCA_ASN1_EXPLICIT	                   0x000200
#define GDCA_ASN1_IMPLICIT                     0x000400
 

int GDCA_Asn1_SizeofDerEncodeUINT32(
    unsigned long data,
    unsigned long *size);

int GDCA_Asn1_SizeofDerEncodeInteger(
    unsigned long dataLen,
    unsigned long firstBit,
    unsigned long *size);
 
int GDCA_Asn1_SizeofDerEncodeExplicit(
    unsigned long dataLen,
    unsigned long *size);
 
int GDCA_Asn1_SizeofDerEncodeImplicit(
    unsigned long dataLen,
    unsigned long *size);
 
int GDCA_Asn1_SizeofDerEncodeBitString(
    unsigned long dataLen,
    unsigned long *size);
  
int GDCA_Asn1_SizeofDerEncodeString(
    unsigned long dataLen,
    unsigned long *size);
 
int GDCA_Asn1_SizeofDerEncodeSequence(
    unsigned long dataLen,
    unsigned long *size);

int GDCA_Asn1_SizeofDerEncodeGeneral(
    unsigned long dataLen,
    unsigned long *size);
 
int GDCA_Asn1_SizeofDerEncodeSet(
    unsigned long dataLen,
    unsigned long *size);

int GDCA_Asn1_SizeofDerEncodeOid(
    unsigned long dataLen,
    unsigned long *size);

int GDCA_Asn1_SizeofDerEncodeOidByType(
    unsigned long oidType,
    unsigned long *size);

int GDCA_Asn1_WriteTag(
    unsigned long tagType,
    unsigned char *destBuf,
    unsigned long nowOffset,
    unsigned long *afterOffset); 

int GDCA_Asn1_WriteTL(
    unsigned long tagType,
	unsigned long length,
    unsigned char *destBuf,
    unsigned long nowOffset,
    unsigned long *afterOffset); 
 
int GDCA_Asn1_WriteExplicitTag(
    unsigned long tagValue,
    unsigned char *destBuf,
    unsigned long nowOffset,
    unsigned long *afterOffset); 

int GDCA_Asn1_WriteImplicitTag(
    unsigned long tagValue,
    unsigned long primitive,
    unsigned char *destBuf,
    unsigned long nowOffset,
    unsigned long *afterOffset); 
  
int GDCA_Asn1_WriteLength(
    unsigned long length,
    unsigned char *destBuf,
    unsigned long nowOffset,
    unsigned long *afterOffset); 
 
int GDCA_Asn1_Write_UINT32(
    unsigned long data,
    unsigned char *destBuf,
    unsigned long nowOffset,
    unsigned long *afterOffset); 

int GDCA_Asn1_WriteOidByValue(
    unsigned char *data,
	unsigned long dataLen,
    unsigned char *destBuf,
    unsigned long nowOffset,
    unsigned long *afterOffset);

int GDCA_Asn1_WriteOidByType(
	unsigned long oidType,
    unsigned char *destBuf,
    unsigned long nowOffset,
    unsigned long *afterOffset);
  
int GDCA_Asn1_WriteString(
	unsigned long stringType,
    unsigned char *data,
	unsigned long dataLen,
    unsigned char *destBuf,
    unsigned long nowOffset,
    unsigned long *afterOffset); 

int GDCA_Asn1_ReadTLV(
    unsigned long tagType,
    unsigned char *srcBuf,
    unsigned long nowOffset,
	unsigned char *data,
	unsigned long *dataLen,
    unsigned long *afterOffset);

int GDCA_Asn1_ReadTag(
    unsigned long tagType,
    unsigned char *srcBuf,
    unsigned long nowOffset,
    unsigned long *afterOffset); 
 
int GDCA_Asn1_ReadExplicitTag(
    unsigned long tagValue,
    unsigned char *srcBuf,
    unsigned long nowOffset,
    unsigned long *afterOffset); 

int GDCA_Asn1_ReadImplicitTag(
    unsigned long tagValue,
    unsigned long *primitive,
    unsigned char *srcBuf,
    unsigned long nowOffset,
    unsigned long *afterOffset); 

int GDCA_Asn1_ReadLength(
    unsigned char *srcBuf,
    unsigned long nowOffset,
    unsigned long *afterOffset,
    unsigned long *length); 

int GDCA_Asn1_Read_UINT32(
    unsigned char *srcBuf,
    unsigned long nowOffset,
    unsigned long *afterOffset,
    unsigned long *data); 
  
int GDCA_Asn1_ReadInteger(
    unsigned char *srcBuf,
    unsigned long nowOffset,
	unsigned char *data,
	unsigned long *dataLen,
    unsigned long *afterOffset);

int GDCA_Asn1_ReadString(
    unsigned long hopeStringType,
    unsigned char *srcBuf,
    unsigned long nowOffset,
	unsigned char *data,
	unsigned long *dataLen,
    unsigned long *afterOffset,
	unsigned long *stringType);

int GDCA_Asn1_ReadOidByValue(
    unsigned char *srcBuf,
    unsigned long nowOffset,
	unsigned char *data,
	unsigned long *dataLen,
    unsigned long *afterOffset);

int GDCA_Asn1_ReadOidByType(
    unsigned char *srcBuf,
    unsigned long nowOffset,
	unsigned long *oidType, 
    unsigned long *afterOffset);

int GDCA_Asn1_ReadUtcTime(
    unsigned char *srcBuf,
    unsigned long nowOffset,
	char          *utcTime,
    unsigned long *afterOffset);
 
int GDCA_Asn1_ReadGeneralizedTime(
    unsigned char *srcBuf,
    unsigned long nowOffset,
	char          *generalizedTime,
    unsigned long *afterOffset);
 
int GDCA_Asn1_UtcTime2Stru(
 	char          *utcTime,
	unsigned long *year, 
	unsigned long *month,
	unsigned long *day,
	unsigned long *hour,
	unsigned long *minute,
	unsigned long *second,
    unsigned long *microSecond);
 
int GDCA_Asn1_Stru2UtcTime(
	unsigned long year, 
	unsigned long month,
	unsigned long day,
	unsigned long hour,
	unsigned long minute,
	unsigned long second,
    unsigned long microSecond,
 	char          *utcTime);
 
int GDCA_Asn1_UtcTime2StringTime(
 	char          *utcTime,
	char          *stringTime);
 
int GDCA_Asn1_StringTime2UtcTime(
	char          *stringTime,
 	char          *utcTime);
 
int GDCA_Asn1_GeneralizedTime2Stru(
	char          *generalizedTime,
	unsigned long *year, 
	unsigned long *month,
	unsigned long *day,
	unsigned long *hour,
	unsigned long *minute,
	unsigned long *second,
    unsigned long *microSecond);
 
int GDCA_Asn1_Stru2GeneralizedTime(
	unsigned long year, 
	unsigned long month,
	unsigned long day,
	unsigned long hour,
	unsigned long minute,
	unsigned long second,
    unsigned long microSecond,
	char          *generalizedTime);
 
int GDCA_Asn1_GeneralizedTime2StringTime(
 	char          *generalizedTime,
	char          *stringTime);
 
int GDCA_Asn1_StringTime2GeneralizedTime(
	char          *stringTime,
 	char          *generalizedTime);
 
int GDCA_Asn1_SkipTLV(
    unsigned long tagType,
    unsigned char *srcBuf,
    unsigned long nowOffset,
    unsigned long *afterOffset);

int GDCA_Asn1_SkipTL(
    unsigned long tagType,
    unsigned char *srcBuf,
    unsigned long nowOffset,
    unsigned long *afterOffset);

int GDCA_Asn1_SkipT(
    unsigned long tagType,
    unsigned char *srcBuf,
    unsigned long nowOffset,
    unsigned long *afterOffset);

int GDCA_Asn1_TestTag(
    unsigned long tagType,
    unsigned char *srcBuf,
    unsigned long nowOffset,
    unsigned long *yes);
  
int GDCA_Asn1_TestExplicitTag(
    unsigned long tagValue,
    unsigned char *srcBuf,
    unsigned long nowOffset,
    unsigned long *yes); 

int GDCA_Asn1_TestImplicitTag(
    unsigned long tagValue,
    unsigned long primitive,
    unsigned char *srcBuf,
    unsigned long nowOffset,
    unsigned long *yes); 

int GDCA_Asn1_OidType2OidValue(
    unsigned long oidType,
    unsigned char *oidValue,
    unsigned long *oidValueLen);
 
int GDCA_Asn1_OidValue2OidType(
    unsigned char *oidValue,
    unsigned long oidValueLen,
	unsigned long *oidType);

int GDCA_Asn1_GetOidLength(
    unsigned long oidType,
    unsigned long *oidLen);

int GDCA_Asn1_ReadBitString(
    unsigned char *srcBuf,
    unsigned long nowOffset,
	unsigned char *data,
	unsigned long *dataLen,
    unsigned long *afterOffset);

int GDCA_Asn1_ReadBool(
    unsigned char *srcBuf,
    unsigned long nowOffset,
	unsigned long *data,
    unsigned long *afterOffset);

int GDCA_berStr2oidStr(
	unsigned char *der_oid,unsigned long der_oid_len,
	char *oid_str,unsigned long *oid_str_len);

int GDCA_Asn1_CountLength(
	unsigned long tagLen,
    unsigned long length,
	unsigned long dataLen,
    unsigned long *sumLen);

int GDCA_ReplacePkcs7OID(
		char *oidStr,
		unsigned char *input,
		unsigned long inputLen,
		unsigned char *output,
		unsigned long *outputLen);

int GDCA_ReplaceSM2Pkcs7SignedOID(
		unsigned long flag,
		unsigned char *input,
		unsigned long inputLen,
		unsigned char *output,
		unsigned long *outputLen);

//check type of P7
int GDCA_IsSM2Pkcs7Type(
		unsigned char *inData,
		unsigned long inDataLen);

#ifdef __cplusplus
}
#endif

#endif
