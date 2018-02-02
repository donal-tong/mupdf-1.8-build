#ifndef _GDCA_OPENSSL_CERT_
#define _GDCA_OPENSSL_CERT_

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/bio.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

/*¶¨ÒåÖ¤Êé½âÎöÐÅÏ¢*/
#define GDCA_GET_CERT_INFO 0x0005
#define GDCA_GET_CERT_VERSION 0x0006
#define GDCA_GET_CERT_SERIAL 0x0007
#define GDCA_GET_CERT_SIGNATURE_ALGO 0x0008
#define GDCA_GET_CERT_ISSUER 0x0009
#define GDCA_GET_CERT_VALID_TIME 0x0010
#define GDCA_GET_CERT_SUBJECT 0x0011
#define GDCA_GET_CERT_PUBLIC_KEY 0x0012
#define GDCA_GET_CERT_EXTENSIONS 0x0013

#define GDCA_GET_CERT_ISSUER_CN		0x0021
#define GDCA_GET_CERT_ISSUER_O		0X0022
#define GDCA_GET_CERT_ISSUER_OU		0X0023
#define GDCA_GET_CERT_SUBJECT_CN	0x0031
#define GDCA_GET_CERT_SUBJECT_O		0X0032
#define GDCA_GET_CERT_SUBJECT_OU	0X0033
#define GDCA_GET_CERT_SUBJECT_EMAIL 0X0034

#define GDCA_GET_CERT_EXT_AUTHORITYKEYIDENTIFIER_INFO         0x0011       //°ä·¢ÕßÃÜÔ¿±êÊ¶·û
#define GDCA_GET_CERT_EXT_SUBJECTKEYIDENTIFIER_INFO           0x0012       //Ö¤Êé³ÖÓÐÕßÃÜÔ¿±êÊ¶·û
#define GDCA_GET_CERT_EXT_KEYUSAGE_INFO					      0x0013       //ÃÜÔ¿ÓÃÍ¾
#define GDCA_GET_CERT_EXT_PRIVATEKEYUSAGEPERIOD_INFO          0x0014	   //Ë½Ô¿ÓÐÐ§ÆÚ
#define GDCA_GET_CERT_EXT_CERTIFICATEPOLICIES_INFO            0x0015       //Ö¤Êé²ßÂÔ
#define GDCA_GET_CERT_EXT_POLICYMAPPINGS_INFO                 0x0016       //²ßÂÔÓ³Éä
#define GDCA_GET_CERT_EXT_BASICCONSTRAINTS_INFO               0x0017       //»ù±¾ÏÞÖÆ
#define GDCA_GET_CERT_EXT_POLICYCONTRAINTS_INFO               0x0018       //²ßÂÔÏÞÖÆ
#define GDCA_GET_CERT_EXT_EXTKEYUSAGE_INFO                    0x0019       //À©Õ¹ÃÜÔ¿ÓÃÍ¾
#define GDCA_GET_CERT_EXT_CRLDISTRIBUTIONPOINTS_INFO          0x001A       //CRL·¢²¼µã
#define GDCA_GET_CERT_EXT_NETSCAPE_CERT_TYPE_INFO             0x001B       //NetscapeÊôÐÔ
#define GDCA_GET_CERT_EXT_SELFDEFINED_EXTENSION_INFO          0x001C       //Ë½ÓÐµÄ×Ô¶¨ÒåÀ©Õ¹Ïî

int Utf8ToGb2312(char **szOut, const char *szIn);

int UnicodeToGb2312(char **szOut, const wchar_t *szIn);

int parseAsnString(ASN1_STRING *asn1String,char *buf,unsigned long *bufLen);

int parseX509Name(X509_NAME *name,char *buf,unsigned long *bufLen);

//È¡Ö¤Êé°æ±¾ºÅ
int Internal_Do_GetCertVersion( 
	X509 *xcert,
	unsigned char *version,
	unsigned long *versionLen);

//È¡Ç©ÃûËã·¨
int Internal_Do_GetCertSignatureAlgo(
    X509 *xcert,
	unsigned char *signAlg,
	unsigned long *signAlgLen);

//È¡Ö¤ÊéÐòÁÐºÅ
int Internal_Do_GetCertSerial(
    X509 *xcert,
	unsigned char *serial,
	unsigned long *serialLen);

//È¡CAÃû³Æ
int Internal_Do_GetCertIssuer(
    X509 *xcert,
	unsigned char *issuer,
	unsigned long *issuerLen);

//È¡Ö¤Êé³ÖÓÐÕßÃû³Æ
int Internal_Do_GetCertSubject(
    X509 *xcert,
	unsigned char *subject,
    unsigned long *subjectLen);

//取证书有效期
int Internal_Do_GetCertValidTime(
    X509 *xcert,
	unsigned char *startTime,
    unsigned long *startTimeLen,
	unsigned char *endTime,
    unsigned long *endTimeLen);

//È¡¹«Ô¿ÐÅÏ¢
int Internal_Do_GetCertPublicKey(
    X509 *xcert,
	unsigned char *publicKey,
    unsigned long *publicKeyLen);

//È¡Ö¤ÊéÀ©Õ¹ÏîÐÅÏ¢
int Internal_Do_GetCertExtensions(
    X509 *xcert,
	unsigned char *extensions,
    unsigned long *extensionsLen);

/*»ñÈ¡Ö¤ÊéDNÏîÐÅÏ¢*/
int Internal_Do_GetCertDN(
	X509 *xcert,
	unsigned long type,
	unsigned char *info,
	unsigned long *infoLen);

int parseASNTime(ASN1_TIME *tm,unsigned char *buf,unsigned long *bufLen);

#ifdef __cplusplus
}
#endif

#endif
