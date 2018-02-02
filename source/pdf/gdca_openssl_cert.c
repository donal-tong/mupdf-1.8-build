
#ifdef _WIN32
#include <windows.h>
#endif

#ifdef _LINUX
#include <locale.h>
#endif


#ifdef _IOS
#include <locale.h>
#endif

#include <openssl/asn1.h>
#include "gdca_openssl_cert.h"

//change UTF8 to GB2312
int Utf8ToGb2312(char **szOut, const char *szIn)
{
	wchar_t *wszBuf=NULL;
	int i=0;

#if defined(_WIN32) 
	i = MultiByteToWideChar(CP_UTF8, 0, szIn, -1, NULL, 0); 
	wszBuf = (wchar_t*)malloc((i+1)*sizeof(wchar_t)); 
	MultiByteToWideChar(CP_UTF8, 0, szIn, -1, wszBuf, i); 
	
	i = WideCharToMultiByte(936, 0, wszBuf, -1, NULL, 0, NULL, NULL); 
	(*szOut) = (char*)malloc((i+1)*sizeof(char)); 
	WideCharToMultiByte(936, 0, wszBuf, -1, *szOut, i, NULL, NULL); 
	free(wszBuf); 
	wszBuf = NULL;
#elif defined(_LINUX) && !defined(_OSX)
	if(NULL==setlocale(LC_ALL,"zh_CN.utf8"))
	{
		return -1;
	}
	i = mbstowcs(NULL, szIn, -1); 
	wszBuf = (wchar_t*)malloc((i+1)*sizeof(wchar_t)); 
	i = mbstowcs(wszBuf, szIn, (i+1)); 
	
	if(NULL==setlocale(LC_ALL,"zh_CN.gbk"))
	{
		return -1;
	}
	i = wcstombs(NULL, wszBuf, -1); 
	(*szOut) = (char*)malloc((i+1)*sizeof(char)); 
	i = wcstombs(*szOut, wszBuf, (i+1)); 
	free(wszBuf); 
	wszBuf = NULL;
#elif defined(_LINUX) && defined(_OSX)
    if(NULL==setlocale(LC_ALL,"zh_CN.UTF-8"))
    {
        return -1;
    }
    i = mbstowcs(NULL, szIn, -1);
    wszBuf = (wchar_t*)malloc((i+1)*sizeof(wchar_t));
    i = mbstowcs(wszBuf, szIn, (i+1));
    
    i = wcstombs(NULL, wszBuf, -1);
    (*szOut) = (char*)malloc((i+1)*sizeof(char));
    i = wcstombs(*szOut, wszBuf, (i+1));
    free(wszBuf);
    wszBuf = NULL;
#elif defined(_IOS)
	if(NULL==setlocale(LC_ALL,"zh_CN.UTF-8"))
	{
		return -1;
	}
	i = mbstowcs(NULL, szIn, -1);
	wszBuf = (wchar_t*)malloc((i+1)*sizeof(wchar_t));
	i = mbstowcs(wszBuf, szIn, (i+1));
	
	i = wcstombs(NULL, wszBuf, -1);
	(*szOut) = (char*)malloc((i+1)*sizeof(char));
	i = wcstombs(*szOut, wszBuf, (i+1));
	free(wszBuf);
	wszBuf = NULL;
#else
	return -1;
#endif
	
	return 0;
}

//change GB2312 to Unicode
int UnicodeToGb2312(char **szOut, const wchar_t *szIn)
{
	int i=0;

#if defined(_WIN32) 
	i = WideCharToMultiByte(936, 0, szIn, -1, NULL, 0, NULL, NULL);
	(*szOut) = (char*)malloc((i+1)*sizeof(char)); 
	WideCharToMultiByte(936, 0, szIn, -1, *szOut, i, NULL, NULL);
#elif defined(_LINUX) && !defined(_OSX)
	if(NULL==setlocale(LC_ALL,"zh_CN.utf8"))
	{
		if(NULL==setlocale(LC_ALL,"zh_CN.utf-8"))
		{
			return -1;
		}
	}
	i = wcstombs(NULL, szIn, -1); 
	(*szOut) = (char*)malloc((i+1)*sizeof(char)); 
	wcstombs(*szOut, szIn, (i+1));
#elif defined(_LINUX) && defined(_OSX)
    
    if(NULL==setlocale(LC_ALL,"zh_CN.UTF-8"))
    {
        return -1;
    }
    i = wcstombs(NULL, szIn, -1);
    (*szOut) = (char*)malloc((i+1)*sizeof(char));
    wcstombs(*szOut, szIn, (i+1));
#elif defined(_IOS)
    if(NULL==setlocale(LC_ALL,"zh_CN.UTF-8"))
	{
		return -1;
	}
	i = wcstombs(NULL, szIn, -1);
	(*szOut) = (char*)malloc((i+1)*sizeof(char));
	wcstombs(*szOut, szIn, (i+1));
#else
	return -1;
#endif 

	return 0;
}

//parse ASN_STRING
int parseAsnString(ASN1_STRING *asn1String,char *buf,unsigned long *bufLen)
{
	unsigned char *tmp_data = NULL;
	int len;
	void *p = NULL;
	char *tmpStr = NULL;
	unsigned long inform;
	ASN1_STRING *pAsnStr = NULL;
	int i, j;
	int rv = 0;
	
	len = ASN1_STRING_length(asn1String);
	p = ASN1_STRING_data(asn1String);
	memcpy(buf, p, len);
	*bufLen = len;
	return 0;

		switch (asn1String->type)
	{
	case V_ASN1_BMPSTRING:
		len = ASN1_STRING_length(asn1String);
		p = ASN1_STRING_data(asn1String);

		tmp_data = (unsigned char *)malloc(2*len+1024);
		if(NULL == tmp_data)
		{
			return -1;
		}
		memset(tmp_data,0,2*len+1024);

		#if defined(_WIN32) 
		//BMPString(BigEnd) to UnicodeString(LittleEnd)
		for (j=0; j<len; j+=2)
		{
			tmp_data[j] = ((unsigned char*)p)[j+1];
			tmp_data[j+1] = ((unsigned char*)p)[j];
		}

		#elif defined(_LINUX)
		for (i=0,j=0; i<len; i+=2,j+=4)
		{
			tmp_data[j] = ((unsigned char*)p)[i+1];
			tmp_data[j+1] = ((unsigned char*)p)[i];
			tmp_data[j+2] = 0;
			tmp_data[j+3] = 0;
		}
		tmp_data[j] = 0;
		tmp_data[j+1] = 0;
		tmp_data[j+2] = 0;
		tmp_data[j+3] = 0;
            
        #elif defined(_IOS)
            for (i=0,j=0; i<len; i+=2,j+=4)
            {
                tmp_data[j] = ((unsigned char*)p)[i+1];
                tmp_data[j+1] = ((unsigned char*)p)[i];
                tmp_data[j+2] = 0;
                tmp_data[j+3] = 0;
            }
            tmp_data[j] = 0;
            tmp_data[j+1] = 0;
            tmp_data[j+2] = 0;
            tmp_data[j+3] = 0;

		#else
			return -1;
		#endif 
			
		//UnicodeString(LittleEnd) to GB2312
		rv = UnicodeToGb2312(&tmpStr, (wchar_t *)tmp_data);
		if(0!=rv)
			return -1;

		memcpy(buf,tmpStr,strlen(tmpStr));
		*bufLen = strlen(tmpStr);
		free(tmp_data);
		free(tmpStr);
		break;
	case V_ASN1_UTF8STRING:
		len = ASN1_STRING_length(asn1String);
		p = ASN1_STRING_data(asn1String);
		memcpy(buf,p,strlen(p));
		*bufLen = strlen(p);

		//UTF8 to GB2312
		// Utf8ToGb2312(&tmpStr, p);
		// memcpy(buf,tmpStr,strlen(tmpStr));
		// *bufLen = strlen(tmpStr);
		// free(tmpStr);
		break;
	default:

		len = ASN1_STRING_length(asn1String);
		p = ASN1_STRING_data(asn1String);

		//to utf8
		if(V_ASN1_PRINTABLESTRING == asn1String->type) inform = MBSTRING_ASC;
		else if(V_ASN1_IA5STRING == asn1String->type) inform = MBSTRING_ASC;
		else if(V_ASN1_T61STRING == asn1String->type) inform = MBSTRING_ASC;
		else if(V_ASN1_UNIVERSALSTRING == asn1String->type) inform = MBSTRING_UNIV;
		else inform = MBSTRING_UTF8;

		ASN1_mbstring_copy(&pAsnStr, p, len, inform, B_ASN1_UTF8STRING);
		
		len = ASN1_STRING_length(pAsnStr);
		p = ASN1_STRING_data(pAsnStr);
		memcpy(buf,p,strlen(p));
		*bufLen = strlen(p);

		//UTF8 to GB2312
		// Utf8ToGb2312(&tmpStr, p);

		// memcpy(buf,tmpStr,strlen(tmpStr));
		// *bufLen = strlen(tmpStr);
		// free(tmpStr);

		ASN1_STRING_free(pAsnStr);

		break;
	}
	return 0;
}

//parse X509 name
int parseX509Name(X509_NAME *name,char *buf,unsigned long *bufLen)
{
	X509_NAME_ENTRY *entry=NULL;
	ASN1_OBJECT *obj=NULL;
	ASN1_STRING *asn1String=NULL;
	unsigned long len;
	char *tmpStr = NULL;
	int i, count;
	int nid;
	const char *s = NULL;
	unsigned long offset = 0;
	int rv = 0;

	//get num of subject entry
	count = X509_NAME_entry_count(name);
	for (i=0; i<count; i++)
	{
		entry = X509_NAME_get_entry(name, i);
		asn1String = X509_NAME_ENTRY_get_data(entry);
		obj = X509_NAME_ENTRY_get_object(entry);
		nid = OBJ_obj2nid(obj);
		s = OBJ_nid2sn(nid);

		buf[offset] = '/';
		offset += 1;
		memcpy(buf+offset,s,strlen(s));
		offset += strlen(s);
		buf[offset] = '=';
		offset += 1;

		rv = parseAsnString(asn1String,&buf[offset],&len);
		if(0!=rv)
			return -1;

		offset += len;
	}

	buf[offset] = '\0';
	*bufLen = offset;

	return 0;
}

//get verison of certificate
int Internal_Do_GetCertVersion( 
	X509 *xcert,
	unsigned char *version,
	unsigned long *versionLen)
{
	int v = -1;
	
	v = (unsigned char)X509_get_version(xcert);
	if( v<0)
	{
		return -1;
	}
	
	version[0] = 'V';
	sprintf(&version[1],"%d", v + 1);
	version[2] = '\0';
	*versionLen = 2;
	return 0;
}

//get signature algorithm of certificate
int Internal_Do_GetCertSignatureAlgo(
    X509 *xcert,
	unsigned char *signAlg,
	unsigned long *signAlgLen)
{
	i2t_ASN1_OBJECT(signAlg,1024,xcert->cert_info->signature->algorithm);
	*signAlgLen = strlen(signAlg);
	return 0;
	
}

//get serial of certificate
int Internal_Do_GetCertSerial(
    X509 *xcert,
	unsigned char *serial,
	unsigned long *serialLen)
{
	ASN1_INTEGER *sN = NULL;
	int i,j;

	sN = X509_get_serialNumber(xcert);
	if( NULL == sN)
	{
		return -1;
	}

	j = 0;
	for(i=0;i<sN->length;i++)
	{
		sprintf(&serial[j],"%02x", sN->data[i]);
		j += 2;
	}
	serial[j] = '\0';
	*serialLen = strlen(serial);
	return 0;
}


//get issuer of cetificate
int Internal_Do_GetCertIssuer(
    X509 *xcert,
	unsigned char *issuer,
	unsigned long *issuerLen)
{
	X509_NAME *issName=NULL;
	int rv = 0;

	issName = X509_get_issuer_name(xcert);
	if (issName == NULL)
	{
		return -1;
	}

	rv = parseX509Name(issName,issuer,issuerLen);
	if(0!=rv)
		return -1;

	return 0;
}

//get subject of cetificate
int Internal_Do_GetCertSubject(
    X509 *xcert,
	unsigned char *subject,
    unsigned long *subjectLen)
{
	X509_NAME *subName=NULL;
	int rv = 0;

	subName = X509_get_subject_name(xcert);
	if (subName == NULL)
	{
		return -1;
	}

	rv = parseX509Name(subName,subject,subjectLen);
	if(0!=rv)
		return -1;

	return 0;
}

//parse asnTime
int parseASNTime(ASN1_TIME *tm,unsigned char *buf,unsigned long *bufLen)
{
	char *v;
	int gmt=0;
	int i;
	int y=0,M=0,d=0,h=0,m=0,s=0;
	char *f = NULL;
	int f_len = 0;
	int l;
	
	if(tm->type == V_ASN1_UTCTIME) 
	{
		i=tm->length;
		v=tm->data;

		if (i < 10) goto err;
		if (v[i-1] == 'Z') gmt=1;
		for (i=0; i<10; i++)
			if ((v[i] > '9') || (v[i] < '0')) goto err;
		y= (v[0]-'0')*10+(v[1]-'0');
		if (y < 50) y+=100;
		M= (v[2]-'0')*10+(v[3]-'0');
		if ((M > 12) || (M < 1)) goto err;
		d= (v[4]-'0')*10+(v[5]-'0');
		h= (v[6]-'0')*10+(v[7]-'0');
		m=  (v[8]-'0')*10+(v[9]-'0');
		if (tm->length >=12 &&
		    (v[10] >= '0') && (v[10] <= '9') &&
		    (v[11] >= '0') && (v[11] <= '9'))
			s=  (v[10]-'0')*10+(v[11]-'0');

		h += 8;   //change to beijing time

		if(h>=24)
		{
			d += 1;
			h -= 24;
		}

		sprintf(buf,"%2d-%2d-%02d:%02d:%02d:%02d",y+1900,M,d,h,m,s);
		*bufLen = strlen(buf);
		return 0;
	}
	if(tm->type == V_ASN1_GENERALIZEDTIME)
	{
		i=tm->length;
		v=(char *)tm->data;

		if (i < 12) goto err;
		if (v[i-1] == 'Z') gmt=1;
		for (i=0; i<12; i++)
			if ((v[i] > '9') || (v[i] < '0')) goto err;
		y= (v[0]-'0')*1000+(v[1]-'0')*100 + (v[2]-'0')*10+(v[3]-'0');
		M= (v[4]-'0')*10+(v[5]-'0');
		if ((M > 12) || (M < 1)) goto err;
		d= (v[6]-'0')*10+(v[7]-'0');
		h= (v[8]-'0')*10+(v[9]-'0');
		m=  (v[10]-'0')*10+(v[11]-'0');
		if (tm->length >= 14 &&
		    (v[12] >= '0') && (v[12] <= '9') &&
		    (v[13] >= '0') && (v[13] <= '9'))
			{
			s=  (v[12]-'0')*10+(v[13]-'0');

			// Check for fractions of seconds.
			if (tm->length >= 15 && v[14] == '.')
				{
				l = tm->length;
				f = &v[14];	/* The decimal point. */
				f_len = 1;
				while (14 + f_len < l && f[f_len] >= '0' && f[f_len] <= '9')
					++f_len;
				}
			}

		h += 8;   //change to beijing time

		if(h>=24)
		{
			d += 1;
			h -= 24;
		}

		if(y>1900)
			sprintf(buf,"%2d-%2d-%02d %02d %02d:%2d",y,M,d,h,m,s);
		else
			sprintf(buf,"%2d-%2d-%02d %02d %02d:%2d",y+1900,M-1,d,h,m,s);
		*bufLen = strlen(buf);
		return 0;
	}

err:
		return -1;
}

int Internal_Do_GetCertValidTime(
    X509 *xcert,
	unsigned char *startTime,
    unsigned long *startTimeLen,
	unsigned char *endTime,
    unsigned long *endTimeLen)
{
	ASN1_TIME *notbefore=NULL;
	ASN1_TIME *notafter=NULL;
	unsigned long offset = 0;
	unsigned long len;
	
	notbefore = X509_get_notBefore(xcert);
	notafter = X509_get_notAfter(xcert);

	parseASNTime(notbefore,startTime,startTimeLen);
	startTime[*startTimeLen] = '\0';
	
	parseASNTime(notafter,endTime,endTimeLen);
	endTime[*endTimeLen] = '\0';

	return 0;
}

//get public key of cetificate
int Internal_Do_GetCertPublicKey(
    X509 *xcert,
	unsigned char *publicKey,
    unsigned long *publicKeyLen)
{
    /*
	EVP_PKEY *pubkey = NULL;
	RSA *rsa = NULL;
	unsigned long i,j;
	unsigned char buf[1024];
	unsigned long bufLen;
	unsigned char *p = buf;
	
	pubkey = X509_get_pubkey(xcert);
	if(NULL == pubkey)
	{
		return -1;
	}

	rsa = EVP_PKEY_get1_RSA(pubkey);
	if(NULL == rsa)
	{
		return -1;
	}

	j = 0;
	bufLen = i2d_RSAPublicKey(rsa,&p);
	for(i=0;i<bufLen;i++)
	{
		sprintf(&publicKey[j],"%02x ",buf[i]);
		j += 3;
	}
	publicKey[j-1] = '\0';
	*publicKeyLen = j-1;
	return 0;
     */
    
    /*
     Modify:hanjieSM2
     Date:2015.05.29
     Developer:zhanghr
     */
    
	int bufLen = 0;
	unsigned char *q = publicKey;
	int rv = -1;
    
	bufLen = i2d_ASN1_BIT_STRING(xcert->cert_info->key->public_key,NULL);
	if(bufLen<= 0)
	{
        return -1;
	}
    
	if(NULL == publicKey)
	{
		*publicKeyLen = bufLen;
        rv = -1;
	}
	else
	{
        
         if(*publicKeyLen < (unsigned int)bufLen)
         {
         *publicKeyLen = bufLen;
        rv = -1;
         }
        
        else
        		{
        *publicKeyLen = i2d_ASN1_BIT_STRING(xcert->cert_info->key->public_key,&q);
        rv = 0;
        		}
	}
    
	return rv;

}

//get extensions of certificate
int Internal_Do_GetCertExtensions(
    X509 *xcert,
	unsigned char *extensions,
    unsigned long *extensionsLen)
{
	X509_EXTENSION *ex = NULL;
	ASN1_OBJECT *obj = NULL;
	BIO *bio = NULL;
	BUF_MEM *bptr = NULL;
    STACK_OF(X509_EXTENSION) *exts = NULL;
	int i,j;
	unsigned long len;

	*extensionsLen = 0;
	exts = xcert->cert_info->extensions;

	bio=BIO_new(BIO_s_mem());

    for (i=0; i<sk_X509_EXTENSION_num(exts); i++)
    {
		ex=sk_X509_EXTENSION_value(exts, i);
		obj=X509_EXTENSION_get_object(ex);

		i2a_ASN1_OBJECT(bio,obj);
		j=X509_EXTENSION_get_critical(ex);
		if (BIO_printf(bio,": %s\n",j?"critical":"") <= 0)
			return 0;
		if(!X509V3_EXT_print(bio, ex, 0,  0))
		{
			M_ASN1_OCTET_STRING_print(bio,ex->value);
		}
		if (BIO_write(bio,"\n",1) <= 0) return -1;
		
	}
	len=BIO_read(bio,extensions,1024);
	BIO_free(bio);
	extensions[len] = '\0';
	*extensionsLen = len;
	return 0;
}

/*获取证书DN项信息*/
int Internal_Do_GetCertDN(
	X509 *xcert,
	unsigned long type,
	unsigned char *info,
	unsigned long *infoLen)
{
	X509_NAME * name = NULL;
	X509_NAME_ENTRY *ne;
	ASN1_STRING *asn1String=NULL;
	int i = 0;
	unsigned char oid[128];
	int ret = -1;
	unsigned char buf[1024];
	unsigned long bufLen = 1024;
	unsigned long num = 0;
	unsigned long len = 0;
	char oidName[128];

	if(GDCA_GET_CERT_ISSUER_CN == type || GDCA_GET_CERT_SUBJECT_CN == type)
		strcpy(oidName,"commonName");
	else if(GDCA_GET_CERT_ISSUER_O == type || GDCA_GET_CERT_SUBJECT_O == type)
		strcpy(oidName,"organizationName");
	else if(GDCA_GET_CERT_ISSUER_OU == type || GDCA_GET_CERT_SUBJECT_OU == type)
		strcpy(oidName,"organizationalUnitName");
	else if(GDCA_GET_CERT_SUBJECT_EMAIL == type)
		strcpy(oidName,"emailAddress");
	else
	{
		return -1;
	}

	if((GDCA_GET_CERT_ISSUER_CN == type) || (GDCA_GET_CERT_ISSUER_O == type) || (GDCA_GET_CERT_ISSUER_OU == type))
		name = X509_get_issuer_name(xcert);
	else
		name = X509_get_subject_name(xcert);
	
	for (i=0; i<sk_X509_NAME_ENTRY_num(name->entries); i++)
	{
		memset(buf,0,bufLen);
		
		ne = sk_X509_NAME_ENTRY_value(name->entries,i);
		OBJ_obj2txt(oid,128,ne->object,0);
		asn1String = X509_NAME_ENTRY_get_data(ne);
		if(0 == strcmp(oid,oidName))
		{
			parseAsnString(asn1String,buf,&bufLen);
			if(num !=0)
			{
				info[len] = '\n';
				len += 1;
			}
			memcpy(info+len,buf,bufLen);
			len += bufLen;
			num++;
		}	
	}

	if(0 == num)
	{
		return -1;
	}
	
	info[len] = '\0';
	*infoLen = len;
	return 0;
}

