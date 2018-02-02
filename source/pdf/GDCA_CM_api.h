#ifndef _GDCA_CM_API_H_
#define _GDCA_CM_API_H_

#ifdef __cplusplus
extern "C" {
#endif

//digest algorithm id
#define SGD_SM3     0x00000001          //SM3
#define SGD_SHA1    0x00000002         //SHA1
#define SGD_SHA256  0x00000004       //SHA256

//asymmetric algorithm id
#define SGD_RSA     0x00010000         //RSA
#define SGD_SM2     0x00020100         //SM2
#define SGD_SM2_1   0x00020200         //SM2 sign
#define SGD_SM2_2   0x00020400         //SM2 key exchange
#define SGD_SM2_3   0x00020800         //SM2 encrypt

//symmetric algorithm id
#define SGD_SM1_ECB         0x00000101       //SM1 ECB
#define SGD_SM1_CBC         0x00000102       //SM1 CBC
#define SGD_SM1_CFB         0x00000104       //SM1 CFB
#define SGD_SM1_OFB         0x00000108       //SM1 OFB
#define SGD_SM1_MAC         0x00000110       //SM1 MAC
#define SGD_SSF33_ECB       0x00000201       //SSF33 ECB
#define SGD_SSF33_CBC       0x00000202       //SSF33 CBC
#define SGD_SSF33_CFB       0x00000204       //SSF33 CFB
#define SGD_SSF33_OFB       0x00000208       //SSF33 OFB
#define SGD_SSF33_MAC       0x00000210       //SSF33 MAC
#define SGD_SM4_ECB         0x00000401       //SM4 ECB
#define SGD_SM4_CBC         0x00000402       //SM4 CBC
#define SGD_SM4_CFB         0x00000404       //SM4 CFB
#define SGD_SM4_OFB         0x00000408       //SM4 OFB
#define SGD_SM4_MAC         0x00000410       //SM4 MAC
#define SGD_ZUC_EEA3        0x00000801       //ZUC 128-EEA3
#define SGD_ZUC_EIA3        0x00000802       //ZUC 128-EIA3

//extended algorithm id
#define SGD_DES_ECB     0x00001001    //DES ECB
#define SGD_DES_CBC     0x00001002    //DES CBC
#define SGD_3DES_ECB    0x00002001   // 3DES EBC
#define SGD_3DES_CBC    0x00002002   // 3DES CBC
#define SGD_AES_ECB     0x00004001    //AES ECB
#define SGD_AES_CBC     0x00004002    //AES CBC

//return value
#define RV_OK                                  0x00000000               //success
#define RV_UnknownErr                  0x01000001               //unknown error
#define RV_NotSupportYetErr          0x01000002              //unsupported service
#define RV_NotInitalizeErr              0x01000003              //not initalize
#define RV_MemoryErr                    0x01000004              //memory error
#define RV_InputErr                        0x01000005              //input error
#define RV_GenRandErr                   0x01000006              //integrity selftest error
#define RV_IntegritySelftestErr      0x01000007             //selftest error
#define RV_RandSelfTestErr            0x01000008             //rand self test error
#define RV_SM2SelfTestErr              0x01000009             //SM2 algorithm self test error
#define RV_SM3SelftestErr               0x0100000a             //SM3 selftest error
#define RV_SM4SelftestErr               0x0100000b             //SM4 selftest error
#define RV_GenKeyErr                     0x0100000c             //key generation error
#define RV_GetKeyErr                      0x0100000d             //read key error
#define RV_SignErr                           0x0100000e             //sign error
#define RV_VerifyErr                        0x0100000f             //verify error
#define RV_EncErr                            0x01000010             //encrypt error
#define RV_DecErr                            0x01000011             //decrypt error
#define RV_DigestErr                        0x01000012             //digest error
#define RV_SymmEncErr                  0x01000013             //symmetric encrypt and decrypt error
#define RV_CreatePWErr                  0x01000014             //create password verifier error
#define RV_CheckPWErr                   0x01000015             //check password error
#define RV_ChangePWErr                 0x01000016             //change pasword error
#define RV_OpenFILEErr                   0x01000017             //open file error
#define RV_ReadFILEErr                   0x01000018             //read file error
#define RV_RemoveFILEErr              0x01000019             //remove file error
#define RV_RightErr                          0x0100001a             //right error
#define RV_CertNotYetValidErr         0x0100001b             //cert not valid yet
#define RV_CertHasExpiredErr         0x0100001c             //cert has expired
#define RV_CertRevokedErr              0x0100001d             //cert has be revoked
#define RV_PKCS7SignErr                 0x0100001e             //P7 sign error
#define RV_PKCS7VerifyErr              0x0100001f            //P7 verify error


#define ECC_MAX_MODULES_BITS_LEN 512                  //max length of SM2 module
#define ECC_MAX_XCOORDINATE_BITS_LEN 512          //max length of x coordinate of SM2 public key
#define ECC_MAX_YCOORDINATE_BITS_LEN 512          //max length of y coordinate of SM2 public key

#define P7_SIGN_TYPE_NO_PLAIN_DATA         1          //PKCS7 sign without plain data
#define P7_SIGN_TYPE_WITH_PLAIN_DATA     2         //PKCS7 sign with plain data

//SM2 public key structure
typedef struct Struct_ECCPUBLICKEYBLOB{
	unsigned long BitLen;
	unsigned char XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];
	unsigned char YCoordinate[ECC_MAX_YCOORDINATE_BITS_LEN/8];
}ECCPUBLICKEYBLOB, *PECCPUBLICKEYBLOB;

//SM2 private key structure
typedef struct Struct_ECCPRIVATEKEYBLOB{
	unsigned long BitLen;
	unsigned char PrivateKey[ECC_MAX_MODULES_BITS_LEN/8];
}ECCPRIVATEKEYBLOB, *PECCPRIVATEKEYBLOB;

//SM2 encrypted data structure
typedef struct Struct_ECCCIPHERBLOB{
	unsigned char XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];
	unsigned char YCoordinate[ECC_MAX_YCOORDINATE_BITS_LEN/8];
	unsigned char HASH[32];
	unsigned long CipherLen;
	unsigned char Cipher[1];
}ECCCIPHERBLOB, *PECCCIPHERBLOB;

//SM2 signature structure
typedef struct Struct_ECCSIGNATUREBLOBL{
	unsigned char r[ECC_MAX_XCOORDINATE_BITS_LEN/8];
	unsigned char s[ECC_MAX_YCOORDINATE_BITS_LEN/8];
}ECCSIGNATUREBLOB, *PERRSIGNATUREBLOB;

//SM2 encrypted data structure
typedef struct Struct_ECCPOINTBLOB{
	unsigned char XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];
	unsigned char YCoordinate[ECC_MAX_YCOORDINATE_BITS_LEN/8];
}ECCPOINTBLOB, *PECCPOINTBLOB;

typedef struct Struct_ENVELOPEDKEYBLOB{
	unsigned long Version;                         //now version is 1
	unsigned long ulSymmAlgID;               //symmetric algorithm id, must be ECB
	unsigned long ulBits;                            //bit length of symmetric key
	unsigned char cbEncryptedPriKey[64]; //encrypted private key
	ECCPUBLICKEYBLOB PubKey;               //public key
	ECCCIPHERBLOB ECCCipherBlob;         //encrypted symmetric key
}ENVELOPEDKEYBLOB, *PENVELOPEDKEYBLOB;

//crypto module information
typedef struct Struct_MODULEINFO{
	unsigned int version;      //version,0xAABBCCCC
	char name[64];
	char Manufacturer[64];   //Manufacturer
}MODULEINFO;

//certificte chain
typedef struct S_CHAIN_LIST_{
	unsigned int certCount;                           //cert num
	unsigned char *certificate[64];               //certificate 
	unsigned int certificateLen[64];              //certificate len
}S_CHAIN_LIST;

enum STATE
{
      OFF_STATE=1, 
      ON_STATE,
      INIT_STATE,
      CO_STATE,
      CSP_INPUT_STATE,
      USER_STATE,
      ASF_STATE,
      SELFTEST_STATE,
      ERROR_STATE,
      PUBLIC_STATE
};

//initialize crypto module
int GDCA_CM_Initialize(char *path);

//finalize crypto module
int GDCA_CM_Finalize(void);

//get crypto module information
int GDCA_CM_GetModuleInfo(
    		char *info,
    		unsigned long *infoLen);

//get crypto module state
int GDCA_CM_GetModuleState(
		unsigned long *state);

//generate random data
int GDCA_CM_GenRandom(
		unsigned char *random,
		unsigned long randomLen);

//create verifier of password
int GDCA_CM_SRP_CalculateVerifier(
		char *username,
		char *password,
		unsigned char *salt,
		unsigned long *saltLen,
		unsigned char *verifier,
		unsigned long *verifierLen);

//create verifier of password
int GDCA_CM_SRP_CalculateB(
		unsigned char *verifier,
		unsigned long verifierLen,
		unsigned char *b,
		unsigned long *bLen,
		unsigned char *B,
		unsigned long *BLen);

//calculate a and A
int GDCA_CM_SRP_CalculateA(
		unsigned char *a,
		unsigned long *aLen,
		unsigned char *A,
		unsigned long *ALen);

//calculate S1 and M1
int GDCA_CM_SRP_CalculateS1(
		char *username,
		char *password,
		unsigned char *salt,
		unsigned long saltLen,
		unsigned char *a,
		unsigned long aLen,
		unsigned char *A,
		unsigned long ALen,
		unsigned char *B,
		unsigned long BLen,
		unsigned char *S1,
		unsigned long *S1Len);

//calculate S2
int GDCA_CM_SRP_CalculateS2(
		unsigned char *verifier,
		unsigned long verifierLen,
		unsigned char *b,
		unsigned long bLen,
		unsigned char *A,
		unsigned long ALen,
		unsigned char *B,
		unsigned long BLen,
		unsigned char *S2,
		unsigned long *S2Len);

//calculate M1
int GDCA_CM_SRP_CalculateM1(
		unsigned char *A,
		unsigned long ALen,
		unsigned char *B,
		unsigned long BLen,
		unsigned char *S1,
		unsigned long S1Len,
		unsigned char *M1,
		unsigned long *M1Len);

//check M1
int GDCA_CM_SRP_CheckM1(
		unsigned char *A,
		unsigned long ALen,
		unsigned char *B,
		unsigned long BLen,
		unsigned char *S2,
		unsigned long S2Len,
		unsigned char *M1,
		unsigned long M1Len);

//calculate M2
int GDCA_CM_SRP_CalculateM2(
		unsigned char *A,
		unsigned long ALen,
		unsigned char *M1,
		unsigned long M1Len,
		unsigned char *S2,
		unsigned long S2Len,
		unsigned char *M2,
		unsigned long *M2Len);

//check M2
int GDCA_CM_SRP_CheckM2(
		unsigned char *A,
		unsigned long ALen,
		unsigned char *M1,
		unsigned long M1Len,
		unsigned char *S1,
		unsigned long S1Len,
		unsigned char *M2,
		unsigned long M2Len);

int GDCA_CM_SRP_ChangePasswordB(
		char *username,
		char *oldPassword,
		unsigned char *oldSalt,
		unsigned long oldSaltLen,
		unsigned char *S1,
		unsigned long S1Len,
		char *newPassword,
		unsigned char *newSalt,
		unsigned long *newSaltLen,
		unsigned char *DVerifier,
		unsigned long *DVerifierLen,
		unsigned char *mac,
		unsigned long *macLen);

int GDCA_CM_SRP_ChangePasswordA(
		unsigned char *oldVerifier,
		unsigned long oldVerifierLen,
		unsigned char *S2,
		unsigned long S2Len,
		unsigned char *newSalt,
		unsigned long newSaltLen,
		unsigned char *DVerifier,
		unsigned long DVerifierLen,
		unsigned char *mac,
		unsigned long macLen,
		unsigned char *newVerifier,
		unsigned long *newVerifierLen);

//generate SM2 key pair
int GDCA_CM_GenSM2KeyPair(
		unsigned char *privateKey,
		unsigned long *privateKeyLen,
		unsigned char *publicKey,
		unsigned long *publicKeyLen);

//generate SM2 key paris segment
int GDCA_CM_GenSM2PrivateKeySegment(
		unsigned char *keyID,
		unsigned long keyIDLen,
		unsigned char *pin,
		unsigned long pinLen,
		unsigned char *appID,
		unsigned long appIDLen,
		unsigned char *mobileID,
		unsigned long mobileIDLen,
    		unsigned char *publicKeySeg,
    		unsigned long *publicKeySegLen);

//import user certificate
int GDCA_CM_ImportCertificate(
		unsigned char *certID,
		unsigned long certIDLen,
		unsigned char *cert,
    		unsigned long certLen);

//get user certificate
int GDCA_CM_GetCertificate(
		unsigned char *certID,
		unsigned long certIDLen,
		unsigned char *cert,
    		unsigned long *certLen);

//delete user certificate
int GDCA_CM_DeleteCertificate(
		unsigned char *certID,
		unsigned long certIDLen);

//verify user certificate
int GDCA_CM_VerifyCertificate(
		unsigned char *usrCert,
    		unsigned long usrCertLen,
    		unsigned char *caCert,
    		unsigned long caCertLen,
    		unsigned char *rootCert,
    		unsigned long rootCertLen,
    		unsigned char *crl,
    		unsigned long crlLen);

//SM2 sign for usr B, step 1
int GDCA_CM_SM2Sign_B1(
		unsigned char *keyID,
		unsigned long keyIDLen,
		unsigned char *pin,
		unsigned long pinLen,
		unsigned char *appID,
		unsigned long appIDLen,
		unsigned char *mobileID,
		unsigned long mobileIDLen,
		unsigned char *hash,
		unsigned long hashLen,
		unsigned char *R1,
		unsigned long R1Len,
		unsigned char *R2,
		unsigned long R2Len,
		unsigned char *k3,
		unsigned long *k3Len,
		unsigned char *k4,
		unsigned long *k4Len,
		unsigned char *r,
		unsigned long *rLen,
		unsigned char *rAlpha,
		unsigned long *rAlphaLen,
		unsigned char *DS1,
		unsigned long *DS1Len);

//SM2 sign for usr B, step 2
int GDCA_CM_SM2Sign_B2(
		unsigned char *keyID,
		unsigned long keyIDLen,
		unsigned char *pin,
		unsigned long pinLen,
		unsigned char *appID,
		unsigned long appIDLen,
		unsigned char *mobileID,
		unsigned long mobileIDLen,
		unsigned char *k3,
		unsigned long k3Len,
		unsigned char *S1,
		unsigned long S1Len,
		unsigned char  *S2,
		unsigned long S2Len,
		unsigned char  *r,
		unsigned long rLen,
		unsigned char *signBlob,
		unsigned long *signBlobLen);

//import SM2 key pair
int GDCA_CM_ImportSM2KeyPair(
		unsigned char *envelopedKeyBlob,
		unsigned long envelopedKeyBlobLen);

//SM2 sign
int GDCA_CM_SM2SignData(
		unsigned char *privateKey,
		unsigned long privateKeyLen,
		unsigned char *inData,
		unsigned long inDataLen,
		unsigned char *signBlob,
		unsigned long *signBlobLen);

//SM2 verify
int GDCA_CM_SM2Verify(
		unsigned char *publicKey,
		unsigned long publicKeyLen,
		unsigned char *inData,
		unsigned long inDataLen,
		unsigned char *signBlob,
		unsigned long signBlobLen);

//SM2 verify with certificate
int GDCA_CM_SM2VerifyByCert(
		unsigned char *cert,
		unsigned long certLen,
		unsigned char *inData,
		unsigned long inDataLen,
		unsigned char *signBlob,
		unsigned long signBlobLen);

//SM2 encrypt
int GDCA_CM_SM2Encrypt(
		unsigned char *publicKey,
		unsigned long publicKeyLen,
		unsigned char *inData,
		unsigned long inDataLen,
		unsigned char *outData,
		unsigned long *outDataLen);

//SM2 encrypt
int GDCA_CM_SM2EncryptWithCert(
		unsigned char *cert,
		unsigned long certLen,
		unsigned char *inData,
		unsigned long inDataLen,
		unsigned char *outData,
		unsigned long *outDataLen);

//SM2 decrypt
int GDCA_CM_SM2Decrypt(
		unsigned char *privateKey,
		unsigned long privateKeyLen,
		unsigned char *inData,
		unsigned long inDataLen,
		unsigned char *outData,
		unsigned long *outDataLen);

//SM2 decrypt for usr B
int GDCA_CM_SM2Decrypt_B1(
		unsigned char *keyID,
		unsigned long keyIDLen,
		unsigned char *pin,
		unsigned long pinLen,
		unsigned char *appID,
		unsigned long appIDLen,
		unsigned char *mobileID,
		unsigned long mobileIDLen,
		unsigned char *u1Data,
		unsigned long u1DataLen,
		unsigned char *inData,
		unsigned long inDataLen,
		unsigned char *outData,
		unsigned long *outDataLen);

//digest init
int GDCA_CM_DigestInit(
		void **hHash,
		unsigned long algID,
		unsigned char *pubKey,
		unsigned long pubKeyLen,
		unsigned char *ID,
		unsigned long IDLen);

//digest for single group data
int GDCA_CM_Digest(
		void *hHash,
		unsigned char *inData,
		unsigned long inDataLen,
		unsigned char *outHash,
		unsigned long *outHashLen);

//update digest for multiple group data
int GDCA_CM_DigestUpdate(
		void *hHash,
		unsigned char *inData,
		unsigned long inDataLen);

//final digest for multiple group data
int GDCA_CM_DigestFinal(
		void *hHash,
		unsigned char *outHash,
		unsigned long *outHashLen);

//set plaintext summetric key
int GDCA_CM_SetSymmKey(
		void **hKey,
		unsigned char *key,
		unsigned long keyLen);

//init of symmetic encrypt
int GDCA_CM_EncryptInit(
		void *hKey,
		unsigned long algID,
		unsigned char *IV,
		unsigned long IVLen);

//symmetric encrypt for single data
int GDCA_CM_Encrypt(
		void *hKey,
		unsigned char *inData,
		unsigned long inDataLen,
		unsigned char *outData,
		unsigned long *outDataLen);

//update symmetric encrypt for multiple data
int GDCA_CM_EncryptUpdate(
		void *hKey,
		unsigned char *inData,
		unsigned long inDataLen,
		unsigned char *outData,
		unsigned long *outDataLen);

//final symmetric encrypt for multiple data
int GDCA_CM_EncryptFinal(
		void *hKey,
		unsigned char *outData,
		unsigned long *outDataLen);

//init of symmetic decrypt
int GDCA_CM_DecryptInit(
		void *hKey,
		unsigned long algID,
		unsigned char *IV,
		unsigned long IVLen);

//symmetric decrypt for single data
int GDCA_CM_Decrypt(
		void *hKey,
		unsigned char *inData,
		unsigned long inDataLen,
		unsigned char *outData,
		unsigned long *outDataLen);

//update symmetric decrypt for multiple data
int GDCA_CM_DecryptUpdate(
		void *hKey,
		unsigned char *inData,
		unsigned long inDataLen,
		unsigned char *outData,
		unsigned long *outDataLen);

//final symmetric decrypt for multiple data
int GDCA_CM_DecryptFinal(
		void *hKey,
		unsigned char *outData,
		unsigned long *outDataLen);

//close handle for digest/HMAC/symetric encrypt
int GDCA_CM_CloseHandle(
		void *hKey);

//encode SM2 sign data
int GDCA_CM_SM2EncodeSignedData(
		unsigned long signType,
		unsigned char  *usrCert,
		unsigned long usrCertLen,
		unsigned char *certChainList,
		unsigned long certChainListLen,
		unsigned char *inData,
		unsigned long inDataLen,
		unsigned char *signBlob,
		unsigned long signBlobLen,
		unsigned char *signedData,
		unsigned long *signedDataLen);

//verify SM2 signed data
int GDCA_CM_SM2VerifySignedData(
		unsigned char *signedData,
		unsigned long signedDataLen,
		unsigned char *inData,
		unsigned long inDataLen);

//get SM2 public key for private key encrow
int GDCA_CM_PKE_GetSM2PublicKey(
		unsigned char *usrInfo,
		unsigned int usrInfoLen,
		unsigned char *pin,
		unsigned int pinLen,
		unsigned char *rand,
		unsigned int randLen,
		unsigned char *publicKey,
		unsigned int *publicKeyLen);

//SM2 decrypt--decrypt C1
int GDCA_CM_PKE_SM2Decrypt_GetXY2(
		unsigned char *usrInfo,
		unsigned int usrInfoLen,
		unsigned char *pin,
		unsigned int pinLen,
		unsigned char *rand,
		unsigned int randLen,
		unsigned char *C1,
		unsigned int C1Len,
		unsigned char *xy2,
		unsigned int *xy2Len);

//SM2 sign for private key encrow
int GDCA_CM_PKE_SM2Sign(
		unsigned char *usrInfo,
		unsigned int usrInfoLen,
		unsigned char *pin,
		unsigned int pinLen,
		unsigned char *rand,
		unsigned int randLen,
		unsigned char *hash,
		unsigned int hashLen,
		unsigned char *signBlob,
		unsigned int *signBlobLen);



#ifdef __cplusplus
}
#endif
																
#endif


