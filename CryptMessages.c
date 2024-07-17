/*
* Copyright(C) 2000-2010 Проект ИОК
*
* Этот файл содержит информацию, являющуюся
* собственностью компании КриптоПро.
*
* Программный код, содержащийся в этом файле, предназначен
* исключительно для целей обучения и не может быть использован
* для защиты информации.
*
* Компания КриптоПро не несет никакой
* ответственности за функционирование этого кода.
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

// Начало примера (не следует удалять данный комментарий, он используется 
// для автоматической сборки документации)
//--------------------------------------------------------------------
// Пример кода для зашифрования данных и создания зашифрованного 
// сообщения при помощи функции CryptEncryptMessage.

// Для функционирования данного кода необходимы:
// - контейнер с ключом AT_KEYEXCHANGE в провайдере PROV_GOST_2012_256
// - сертификат этого ключа, установленный в хранилище пользователя ("MY")
//--------------------------------------------------------------------

#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

static void CleanUp(void);
static void HandleError(const char *s);
static PCCERT_CONTEXT GetRecipientCert(HCERTSTORE hCertStore);
static void DecryptMessage(BYTE *pbEncryptedBlob, DWORD cbEncryptedBlob, FILE *writeHere);
static void GetCertDName(PCERT_NAME_BLOB pNameBlob, char **pszName);

static HCRYPTPROV hCryptProv = 0;        // дескриптор CSP 
static HCERTSTORE hStoreHandle = 0;      // дескриптор хранилища сертификатов
static PCCERT_CONTEXT pRecipientCert = NULL;
static char *szDName = NULL;		  // DName сертификата

int main(int argc, char *argv[])
{
    //Задание переменных для чтения из файла
    FILE* hFile;
    long fileSize;
    BYTE* pbContent;

    if (argc != 3 || argv[1] == NULL || argv[2] == NULL) {
        HandleError("The file name or CN is absent.\n");
    }
    //char* targetCN = "CN=";
    //targetCN = strcat(targetCN, argv[2]);
    char* targetCN = argv[2];
    // Открытие файла.
    if (!(hFile = fopen(argv[1], "rb"))) {
        HandleError("Error opening input file");
    }
    printf("The file %s was opened\n", argv[1]);
    // Определение размера файла.
    fseek(hFile, 0, SEEK_END);
    fileSize = ftell(hFile);
    fseek(hFile, 0, SEEK_SET);
    // Выделение памяти для pbContent.
    pbContent = (BYTE*)malloc(fileSize);
    if (pbContent == NULL) {
        HandleError("Memory allocation failed");
    }

    // Чтение данных из файла в pbContent.
    if (fread(pbContent, 1, fileSize, hFile) != fileSize) {
        HandleError("Error reading file");
    }

    // Закрытие файла.
    fclose(hFile);
    // Вывод содержимого файла.
    // printf("File content:\n");
    // for (long i = 0; i < fileSize; i++) {
    //     printf("%c", pbContent[i]);
    // }
    // printf("\n");

    DWORD cbContent = fileSize + 1;	   // Длина сообщения, включая конечный 0

    //оригинал
    // BYTE pbContent[] = "Hello, world!"; // Сообщение
    // DWORD cbContent = sizeof(pbContent); 

    CRYPT_ALGORITHM_IDENTIFIER EncryptAlgorithm;
    CRYPT_ENCRYPT_MESSAGE_PARA EncryptParams;

    BYTE*    pbEncryptedBlob = NULL;
    DWORD    cbEncryptedBlob;

    printf("source message: %s\n", pbContent);
    printf("message length: %d bytes \n", cbContent);

    // Получение дескриптора криптографического провайдера.
    if(!CryptAcquireContext(
	&hCryptProv,         // Адрес возврашаемого дескриптора.
	0,                // Используется имя текущего зарегестрированного пользователя.
	NULL,                // Используется провайдер по умолчанию.
	PROV_GOST_2012_256,   // Необходимо для зашифрования и подписи.
	CRYPT_VERIFYCONTEXT))		     // Никакие флаги не нужны.
    {
	HandleError("Cryptographic context could not be acquired.");
    }
    printf("CSP has been acquired. \n");

    // Открытие системного хранилища сертификатов.
    hStoreHandle = CertOpenSystemStore(hCryptProv, _TEXT("MY"));

    if(!hStoreHandle)
    {
	HandleError( "Error getting store handle.");
    }
    printf("The MY store is open. \n");

    // Получение указателя на сертификат получателя с помощью
    // функции GetRecipientCert. 
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
    //strcat чтобы при поиске имени "name" проверка не проходила при 
    //переданном параметре "nam", а также если один из других параметров сертификата
    //содержит в себе "name"
    strcat(targetCN, ", OU");
    // Проверка совпадения CN
    if (!strstr(szDName, targetCN)) {
        printf("CN does not match. Encryption aborted.\n");
        CleanUp();
        return 1;
    }

    // Инициализация структуры с нулем.
    memset(&EncryptAlgorithm, 0, sizeof(CRYPT_ALGORITHM_IDENTIFIER));
    //EncryptAlgorithm.pszObjId = OID_CipherVar_Default;  
    EncryptAlgorithm.pszObjId = szOID_CP_GOST_28147;  

    // Инициализация структуры CRYPT_ENCRYPT_MESSAGE_PARA. 
    memset(&EncryptParams, 0, sizeof(CRYPT_ENCRYPT_MESSAGE_PARA));
    EncryptParams.cbSize =  sizeof(CRYPT_ENCRYPT_MESSAGE_PARA);
    EncryptParams.dwMsgEncodingType = MY_ENCODING_TYPE;
    EncryptParams.hCryptProv = hCryptProv;
    EncryptParams.ContentEncryptionAlgorithm = EncryptAlgorithm;

    // Вызов функции CryptEncryptMessage.
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

    // Распределение памяти под возвращаемый BLOB.
    pbEncryptedBlob = (BYTE*)malloc(cbEncryptedBlob);

    if(!pbEncryptedBlob)
	HandleError("Memory allocation error while encrypting.");

    // Повторный вызов функции CryptEncryptMessage для зашифрования содержимого.
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
    // Вызов функции DecryptMessage, код которой описан после main, для расшифрования сообщения.
    DecryptMessage(pbEncryptedBlob, cbEncryptedBlob, writeHere);
    fclose(writeHere);
    CleanUp();
    return 0;
}

//  Определение функции DecryptMessage.
// Пример функции для расшифрования зашифрованного сообщения с 
// использованием функции CryptDecryptMessage. ЕЕ параметрами являются
// pbEncryptedBlob, зашифрованное сообщение; cbEncryptedBlob, длина
// этого сообщения
void DecryptMessage(BYTE *pbEncryptedBlob, DWORD cbEncryptedBlob, FILE *writeHere)
{
    DWORD cbDecryptedMessage;
    CRYPT_DECRYPT_MESSAGE_PARA  decryptParams;

    BYTE*  pbDecryptedMessage = NULL;

    // Получение указателя на зашифрованное сообщение, pbEncryptedBlob,
    // и его длину, cbEncryptedBlob. В этом примере они устанавливаются
    // как параметры совместно с  CSP и дескриптором открытого хранилища.
    // Просмотр зашифрованного BLOBа.
    char * ep = getenv("COLUMNS");
    int brk;
    int i;
    brk = ep ? atoi(ep) : 80;
    brk = ((brk <= 3) ? 80 : brk) / 3;
    
    //Запись
    for(i = 0; i < (int)cbEncryptedBlob; i++)
        printf("%02x%c",pbEncryptedBlob[i],(i%brk == (brk - 1))?'\n':' ');
    printf("\n");

    //   В этом примере дескриптор хранилище MY установлен как параметр. 

    //   Инициализация структуры CRYPT_DECRYPT_MESSAGE_PARA.
    memset(&decryptParams, 0, sizeof(CRYPT_DECRYPT_MESSAGE_PARA));
    decryptParams.cbSize = sizeof(CRYPT_DECRYPT_MESSAGE_PARA);
    decryptParams.dwMsgAndCertEncodingType = MY_ENCODING_TYPE;
    decryptParams.cCertStore = 1;
    decryptParams.rghCertStore = &hStoreHandle;

    //  Расшифрование сообщения

    //  Вызов фнукции CryptDecryptMessage для получения возвращаемого размера данных.
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

    // Выделение памяти под возвращаемые расшифрованные данные.
    pbDecryptedMessage = (BYTE*)malloc(cbDecryptedMessage);
    if(!pbDecryptedMessage)
    {
	free(pbEncryptedBlob);
	HandleError("Memory allocation error while decrypting");
    }
    // Вызов функции CryptDecryptMessage для расшифрования данных.
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

// Проверка типа провайдера 
static BOOL isGostType(DWORD dwProvType) {
    return IS_GOST_PROV(dwProvType);
}

// GetRecipientCert перечисляет сертификаты в хранилище и находит
// первый сертификат, обладающий ключем AT_EXCHANGE. Если сертификат
// сертификат найден, то возвращается указатель на него.
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
	// Поиск сертификатов в хранилище до тех пор, пока не будет достигнут 
	// конец хранилища, или сертификат с ключем AT_KEYEXCHANGE не будет найден. 
	pCertContext = CertFindCertificateInStore( 
	    hCertStore, // Дескриптор хранилища, в котором будет осуществлен поиск. 
	    MY_ENCODING_TYPE,          
	    0,          
	    CERT_FIND_PROPERTY,
	    &PropId,   
	    pCertContext);
	if ( !pCertContext )
	    break;

	// Для простоты в этом коде реализован только поиск первого 
	// вхождения ключа AT_KEYEXCHANGE. Во многих случаях, помимо 
	// поиска типа ключа, осуществляется также поиск определенного 
	// имени субъекта. 

	// Однократный вызов функции CertGetCertificateContextProperty  
	// для получения возврашенного размера структуры. 
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
	// распределение памяти под возвращенную структуру. 

	free(pKeyInfo);

	pKeyInfo = (CRYPT_KEY_PROV_INFO*)malloc(dwSize);

	if(!pKeyInfo) 
	{ 
	    HandleError("Error allocating memory for pKeyInfo."); 
	} 

	//-------------------------------------------------------------- 
	// Получение структуры информации о ключе. 

	if(!(CertGetCertificateContextProperty( 
	    pCertContext, 
	    CERT_KEY_PROV_INFO_PROP_ID, 
	    pKeyInfo, 
	    &dwSize))) 
	{ 
	    HandleError("The second call to the function failed."); 
	} 

	//------------------------------------------- 
	// Проверка члена dwKeySpec на расширенный ключ и типа провайдера
	if(pKeyInfo->dwKeySpec == AT_KEYEXCHANGE && isGostType(pKeyInfo->dwProvType)) 
	{
	    //-------------------------------------------
	    //попробуем открыть провайдер
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
} // Конец определения GetRecipientCert 

//----------------------------------------------------------------------------
// Получение имени из CERT_NAME_BLOB
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

// Конец примера 
// (не следует удалять данный комментарий, он используется 
//  для автоматической сборки документации)

//  В этом примере используется функция HandleError, функция обработки
//  простых ошибок, для печати сообщения об ошибке в стандартный файл 
//  ошибок (stderr) и выхода из программы. 
//  В большинстве приложений эта функция заменяется другой функцией, 
//  которая выводит более полное сообщение об ошибке.
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
	/* !! удалит hCryptProv */
	if(CertCloseStore(hStoreHandle, CERT_CLOSE_STORE_CHECK_FLAG)) {
	    printf("The MY store was closed without incident. \n");
	} else {
	    printf("Store closed after encryption -- \n"
		   "but not all certificates or CRLs were freed. \n");
	}
    }
    free(szDName);
}
