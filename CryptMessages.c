/*
* Copyright(C) 2000-2010 ������ ���
*
* ���� ���� �������� ����������, ����������
* �������������� �������� ���������.
*
* ����������� ���, ������������ � ���� �����, ������������
* ������������� ��� ����� �������� � �� ����� ���� �����������
* ��� ������ ����������.
*
* �������� ��������� �� ����� �������
* ��������������� �� ���������������� ����� ����.
*/

//gcc -o CryptMessages.exe CryptMessages.c -lcrypt32

#include <stdio.h>
#ifdef _WIN32
#   include <windows.h>
#   include <wincrypt.h>
#   include <tchar.h>
#else
#   include <stdlib.h>
#   include "reader/tchar.h"
#endif
#include <string.h>
#include "WinCryptEx.h"

// ������ ������� (�� ������� ������� ������ �����������, �� ������������ 
// ��� �������������� ������ ������������)
//--------------------------------------------------------------------
// ������ ���� ��� ������������ ������ � �������� �������������� 
// ��������� ��� ������ ������� CryptEncryptMessage.

// ��� ���������������� ������� ���� ����������:
// - ��������� � ������ AT_KEYEXCHANGE � ���������� PROV_GOST_2012_256
// - ���������� ����� �����, ������������� � ��������� ������������ ("MY")
//--------------------------------------------------------------------

#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

static void CleanUp(void);
static void HandleError(const char *s);
static PCCERT_CONTEXT GetRecipientCert(HCERTSTORE hCertStore);
static void DecryptMessage(BYTE *pbEncryptedBlob, DWORD cbEncryptedBlob, FILE *writeHere);
static void GetCertDName(PCERT_NAME_BLOB pNameBlob, char **pszName);

static HCRYPTPROV hCryptProv = 0;        // ���������� CSP 
static HCERTSTORE hStoreHandle = 0;      // ���������� ��������� ������������
static PCCERT_CONTEXT pRecipientCert = NULL;
static char *szDName = NULL;		  // DName �����������

int main(int argc, char *argv[])
{
    //������� ���������� ��� ������ �� �����
    FILE* hFile;
    long fileSize;
    BYTE* pbContent;

    if (argc != 3 || argv[1] == NULL || argv[2] == NULL) {
        HandleError("The file name or CN is absent.\n");
    }
    //char* targetCN = "CN=";
    //targetCN = strcat(targetCN, argv[2]);
    char* targetCN = argv[2];
    // �������� �����.
    if (!(hFile = fopen(argv[1], "rb"))) {
        HandleError("Error opening input file");
    }
    printf("The file %s was opened\n", argv[1]);
    // ����������� ������� �����.
    fseek(hFile, 0, SEEK_END);
    fileSize = ftell(hFile);
    fseek(hFile, 0, SEEK_SET);
    // ��������� ������ ��� pbContent.
    pbContent = (BYTE*)malloc(fileSize);
    if (pbContent == NULL) {
        HandleError("Memory allocation failed");
    }

    // ������ ������ �� ����� � pbContent.
    if (fread(pbContent, 1, fileSize, hFile) != fileSize) {
        HandleError("Error reading file");
    }

    // �������� �����.
    fclose(hFile);
    // ����� ����������� �����.
    // printf("File content:\n");
    // for (long i = 0; i < fileSize; i++) {
    //     printf("%c", pbContent[i]);
    // }
    // printf("\n");

    DWORD cbContent = fileSize + 1;	   // ����� ���������, ������� �������� 0

    //��������
    // BYTE pbContent[] = "Hello, world!"; // ���������
    // DWORD cbContent = sizeof(pbContent); 

    CRYPT_ALGORITHM_IDENTIFIER EncryptAlgorithm;
    CRYPT_ENCRYPT_MESSAGE_PARA EncryptParams;

    BYTE*    pbEncryptedBlob = NULL;
    DWORD    cbEncryptedBlob;

    printf("source message: %s\n", pbContent);
    printf("message length: %d bytes \n", cbContent);

    // ��������� ����������� ������������������ ����������.
    if(!CryptAcquireContext(
	&hCryptProv,         // ����� ������������� �����������.
	0,                // ������������ ��� �������� ������������������� ������������.
	NULL,                // ������������ ��������� �� ���������.
	PROV_GOST_2012_256,   // ���������� ��� ������������ � �������.
	CRYPT_VERIFYCONTEXT))		     // ������� ����� �� �����.
    {
	HandleError("Cryptographic context could not be acquired.");
    }
    printf("CSP has been acquired. \n");

    // �������� ���������� ��������� ������������.
    hStoreHandle = CertOpenSystemStore(hCryptProv, _TEXT("MY"));

    if(!hStoreHandle)
    {
	HandleError( "Error getting store handle.");
    }
    printf("The MY store is open. \n");

    // ��������� ��������� �� ���������� ���������� � �������
    // ������� GetRecipientCert. 
    pRecipientCert = GetRecipientCert(hStoreHandle);

    if(!pRecipientCert)
    {
	printf("No certificate with a CERT_KEY_CONTEXT_PROP_ID \n");
	printf("property and an AT_KEYEXCHANGE private key available. \n");
	printf("While the message could be encrypted, in this case, \n");
	printf("it could not be decrypted in this program. \n");
	printf("For more information, see the documentation for \n");
	printf("CryptEncryptMessage and CryptDecryptMessage.\n\n");
	HandleError( "No Certificate with AT_KEYEXCHANGE key in store.");
    }
    GetCertDName(&pRecipientCert->pCertInfo->Subject, &szDName);
    printf("A recipient's certificate has been acquired: %s\n", szDName);
    printf("The CN is: %s\n", targetCN);
    //strcat ����� ��� ������ ����� "name" �������� �� ��������� ��� 
    //���������� ��������� "nam", � ����� ���� ���� �� ������ ���������� �����������
    //�������� � ���� "name"
    strcat(targetCN, ", OU");
    // �������� ���������� CN
    if (!strstr(szDName, targetCN)) {
        printf("CN does not match. Encryption aborted.\n");
        CleanUp();
        return 1;
    }

    // ������������� ��������� � �����.
    memset(&EncryptAlgorithm, 0, sizeof(CRYPT_ALGORITHM_IDENTIFIER));
    //EncryptAlgorithm.pszObjId = OID_CipherVar_Default;  
    EncryptAlgorithm.pszObjId = szOID_CP_GOST_28147;  

    // ������������� ��������� CRYPT_ENCRYPT_MESSAGE_PARA. 
    memset(&EncryptParams, 0, sizeof(CRYPT_ENCRYPT_MESSAGE_PARA));
    EncryptParams.cbSize =  sizeof(CRYPT_ENCRYPT_MESSAGE_PARA);
    EncryptParams.dwMsgEncodingType = MY_ENCODING_TYPE;
    EncryptParams.hCryptProv = hCryptProv;
    EncryptParams.ContentEncryptionAlgorithm = EncryptAlgorithm;

    // ����� ������� CryptEncryptMessage.
    if(!CryptEncryptMessage(
	&EncryptParams,
	1,
	&pRecipientCert,
	pbContent,
	cbContent,
	NULL,
	&cbEncryptedBlob))
    {
	HandleError( "Getting EncrypBlob size failed.");
    }
    printf("The encrypted message is %d bytes. \n", cbEncryptedBlob);

    // ������������� ������ ��� ������������ BLOB.
    pbEncryptedBlob = (BYTE*)malloc(cbEncryptedBlob);

    if(!pbEncryptedBlob)
	HandleError("Memory allocation error while encrypting.");

    // ��������� ����� ������� CryptEncryptMessage ��� ������������ �����������.
    if(!CryptEncryptMessage(
	&EncryptParams,
	1,
	&pRecipientCert,
	pbContent,
	cbContent,
	pbEncryptedBlob,
	&cbEncryptedBlob))
    {
	HandleError("Encryption failed.");
    }
    printf( "Encryption succeeded. \n");


    FILE *writeHere;
    if (!(writeHere = fopen("output.txt", "w"))) {
        HandleError("Error opening output file");
    }
    // ����� ������� DecryptMessage, ��� ������� ������ ����� main, ��� ������������� ���������.
    DecryptMessage(pbEncryptedBlob, cbEncryptedBlob, writeHere);
    fclose(writeHere);
    CleanUp();
    return 0;
}

//  ����������� ������� DecryptMessage.
// ������ ������� ��� ������������� �������������� ��������� � 
// �������������� ������� CryptDecryptMessage. �� ����������� ��������
// pbEncryptedBlob, ������������� ���������; cbEncryptedBlob, �����
// ����� ���������
void DecryptMessage(BYTE *pbEncryptedBlob, DWORD cbEncryptedBlob, FILE *writeHere)
{
    DWORD cbDecryptedMessage;
    CRYPT_DECRYPT_MESSAGE_PARA  decryptParams;

    BYTE*  pbDecryptedMessage = NULL;

    // ��������� ��������� �� ������������� ���������, pbEncryptedBlob,
    // � ��� �����, cbEncryptedBlob. � ���� ������� ��� ���������������
    // ��� ��������� ��������� �  CSP � ������������ ��������� ���������.
    // �������� �������������� BLOB�.
    char * ep = getenv("COLUMNS");
    int brk;
    int i;
    brk = ep ? atoi(ep) : 80;
    brk = ((brk <= 3) ? 80 : brk) / 3;
    
    //������
    for(i = 0; i < (int)cbEncryptedBlob; i++)
        printf("%02x%c",pbEncryptedBlob[i],(i%brk == (brk - 1))?'\n':' ');
    printf("\n");

    //   � ���� ������� ���������� ��������� MY ���������� ��� ��������. 

    //   ������������� ��������� CRYPT_DECRYPT_MESSAGE_PARA.
    memset(&decryptParams, 0, sizeof(CRYPT_DECRYPT_MESSAGE_PARA));
    decryptParams.cbSize = sizeof(CRYPT_DECRYPT_MESSAGE_PARA);
    decryptParams.dwMsgAndCertEncodingType = MY_ENCODING_TYPE;
    decryptParams.cCertStore = 1;
    decryptParams.rghCertStore = &hStoreHandle;

    //  ������������� ���������

    //  ����� ������� CryptDecryptMessage ��� ��������� ������������� ������� ������.
    if(!CryptDecryptMessage(
	&decryptParams,
	pbEncryptedBlob,
	cbEncryptedBlob,
	NULL,
	&cbDecryptedMessage,
	NULL))
    {
	free(pbEncryptedBlob);
	HandleError( "Error getting decrypted message size");
    }
    printf("The size for the decrypted message is: %d.\n", cbDecryptedMessage);

    // ��������� ������ ��� ������������ �������������� ������.
    pbDecryptedMessage = (BYTE*)malloc(cbDecryptedMessage);
    if(!pbDecryptedMessage)
    {
	free(pbEncryptedBlob);
	HandleError("Memory allocation error while decrypting");
    }
    // ����� ������� CryptDecryptMessage ��� ������������� ������.
    if(!CryptDecryptMessage(
	&decryptParams,
	pbEncryptedBlob,
	cbEncryptedBlob,
	pbDecryptedMessage,
	&cbDecryptedMessage,
	NULL))
    {
	free(pbEncryptedBlob);
	free(pbDecryptedMessage);
	HandleError("Error decrypting the message");
    }

    printf("Message Decrypted Successfully. \n");
    printf("The decrypted string is: %s\n", (LPSTR) pbDecryptedMessage);
    fprintf(writeHere, "%s", (LPSTR) pbDecryptedMessage);

    free(pbEncryptedBlob);
    free(pbDecryptedMessage);
}

// �������� ���� ���������� 
static BOOL isGostType(DWORD dwProvType) {
    return IS_GOST_PROV(dwProvType);
}

// GetRecipientCert ����������� ����������� � ��������� � �������
// ������ ����������, ���������� ������ AT_EXCHANGE. ���� ����������
// ���������� ������, �� ������������ ��������� �� ����.
PCCERT_CONTEXT GetRecipientCert(HCERTSTORE hCertStore) 
{ 
    PCCERT_CONTEXT pCertContext = NULL; 
    BOOL bCertNotFind = TRUE; 
    DWORD dwSize = 0; 
    CRYPT_KEY_PROV_INFO* pKeyInfo = NULL; 
    DWORD PropId = CERT_KEY_PROV_INFO_PROP_ID;
    HCRYPTPROV hProv = 0;
    DWORD dwKeySpec = 0;
    BOOL  fFreeProv = FALSE;

    if(!hCertStore) return NULL;

    do
    { 
	// ����� ������������ � ��������� �� ��� ���, ���� �� ����� ��������� 
	// ����� ���������, ��� ���������� � ������ AT_KEYEXCHANGE �� ����� ������. 
	pCertContext = CertFindCertificateInStore( 
	    hCertStore, // ���������� ���������, � ������� ����� ����������� �����. 
	    MY_ENCODING_TYPE,          
	    0,          
	    CERT_FIND_PROPERTY,
	    &PropId,   
	    pCertContext);
	if ( !pCertContext )
	    break;

	// ��� �������� � ���� ���� ���������� ������ ����� ������� 
	// ��������� ����� AT_KEYEXCHANGE. �� ������ �������, ������ 
	// ������ ���� �����, �������������� ����� ����� ������������� 
	// ����� ��������. 

	// ����������� ����� ������� CertGetCertificateContextProperty  
	// ��� ��������� ������������� ������� ���������. 
	if(!(CertGetCertificateContextProperty( 
	    pCertContext, 
	    CERT_KEY_PROV_INFO_PROP_ID, 
	    NULL, 
	    &dwSize))) 
	{ 
	    printf("Error getting key property.\n"); 
	    return NULL;
	} 

	//-------------------------------------------------------------- 
	// ������������� ������ ��� ������������ ���������. 

	free(pKeyInfo);

	pKeyInfo = (CRYPT_KEY_PROV_INFO*)malloc(dwSize);

	if(!pKeyInfo) 
	{ 
	    HandleError("Error allocating memory for pKeyInfo."); 
	} 

	//-------------------------------------------------------------- 
	// ��������� ��������� ���������� � �����. 

	if(!(CertGetCertificateContextProperty( 
	    pCertContext, 
	    CERT_KEY_PROV_INFO_PROP_ID, 
	    pKeyInfo, 
	    &dwSize))) 
	{ 
	    HandleError("The second call to the function failed."); 
	} 

	//------------------------------------------- 
	// �������� ����� dwKeySpec �� ����������� ���� � ���� ����������
	if(pKeyInfo->dwKeySpec == AT_KEYEXCHANGE && isGostType(pKeyInfo->dwProvType)) 
	{
	    //-------------------------------------------
	    //��������� ������� ���������
	    fFreeProv = FALSE;
	    if ( CryptAcquireCertificatePrivateKey(pCertContext, CRYPT_ACQUIRE_COMPARE_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG, NULL, &hProv, &dwKeySpec, &fFreeProv))
	    {
		HCRYPTKEY hKey = 0;
		if (CryptGetUserKey( hProv, dwKeySpec, &hKey ))
		{
		    bCertNotFind = FALSE;
		    CryptDestroyKey( hKey );
		}
		if (fFreeProv)
		    CryptReleaseContext( hProv, 0 );
	    }
	}
    } while(bCertNotFind && pCertContext);

    free(pKeyInfo);

    if (bCertNotFind)
	return NULL;
    else 
	return (pCertContext); 
} // ����� ����������� GetRecipientCert 

//----------------------------------------------------------------------------
// ��������� ����� �� CERT_NAME_BLOB
void GetCertDName(PCERT_NAME_BLOB pNameBlob, char **pszName) {
    DWORD	cbName;

    cbName = CertNameToStr(
	X509_ASN_ENCODING, pNameBlob,
	CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
	NULL, 0);
    if (cbName == 1)
	HandleError("CertNameToStr(NULL)");

    *pszName = (char *)malloc(cbName * sizeof(char));
    if (!*pszName)
	HandleError("Out of memory.");

    cbName = CertNameToStrA(
	X509_ASN_ENCODING, pNameBlob,
	CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
	*pszName, cbName);
    if (cbName == 1)
	HandleError("CertNameToStr(pbData)");
}

// ����� ������� 
// (�� ������� ������� ������ �����������, �� ������������ 
//  ��� �������������� ������ ������������)

//  � ���� ������� ������������ ������� HandleError, ������� ���������
//  ������� ������, ��� ������ ��������� �� ������ � ����������� ���� 
//  ������ (stderr) � ������ �� ���������. 
//  � ����������� ���������� ��� ������� ���������� ������ ��������, 
//  ������� ������� ����� ������ ��������� �� ������.
void HandleError(const char *s)
{
    DWORD err = GetLastError();
    printf("Error number     : 0x%x\n", err);
    printf("Error description: %s\n", s);
    CleanUp();
    if(!err) err = 1;
    exit(err);
}

void CleanUp(void)
{
    CertFreeCertificateContext(pRecipientCert);
    if (hStoreHandle) 
    {
	/* !! ������ hCryptProv */
	if(CertCloseStore(hStoreHandle, CERT_CLOSE_STORE_CHECK_FLAG)) {
	    printf("The MY store was closed without incident. \n");
	} else {
	    printf("Store closed after encryption -- \n"
		   "but not all certificates or CRLs were freed. \n");
	}
    }
    free(szDName);
}
