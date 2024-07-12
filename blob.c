#include <stdio.h>
#ifdef _WIN32
#   include <windows.h>
#   include <wincrypt.h>
#else
#   include <stdlib.h>
#endif
#include "WinCryptEx.h"

void HandleError(const char *s)
{
	DWORD err = GetLastError();
	printf("Error number     : 0x%x\n", err);
	printf("Error description: %s\n", s);

	getchar();

	if (!err) err = 1;
	exit(err);
}

// #define G28147_KEYLEN 64

static int fill_default_simpleblob(CRYPT_SIMPLEBLOB *blob)
{
	if (blob == NULL) {
		return 0;
	}

	/*BLOBHEADER*/
	blob->tSimpleBlobHeader.BlobHeader.bType = SIMPLEBLOB;
	blob->tSimpleBlobHeader.BlobHeader.bVersion = BLOB_VERSION; // 0x20 current.
	blob->tSimpleBlobHeader.BlobHeader.reserved = 0x0;
	blob->tSimpleBlobHeader.BlobHeader.aiKeyAlg = CALG_G28147; // CALG_G28147_IMIT; 

	blob->tSimpleBlobHeader.Magic = G28147_MAGIC;
	blob->tSimpleBlobHeader.EncryptKeyAlgId = CALG_G28147;

	return 1;
}

/** Magic value for EncryptionParamSet.
* Designated to represent DER-encoded ASN1-structure for GOST 28147 paramset.
* Probably it's corresponds to id-GostR3410-2001-CryptoPro-XchA-ParamSet.
*/
static const BYTE default_params[] = { 0x30, 0x09, 0x06, 0x07,
0x2A, 0x85, 0x03, 0x02,
0x02, 0x1F, 0x01 };


#define DBG_OUT(msg) fprintf(stderr, "MSG %s:%d:%s: %s\n", __FILE__, __LINE__, __FUNCTION__, msg);
#define DBG_OUT_E(msg) fprintf(stderr, "MSG %s:%d:%s: %s : 0x%X\n", __FILE__, __LINE__, __FUNCTION__, msg, GetLastError());

/**
* Converts raw key data to HCRYPTKEY suitable for later usage.
* @param hProvider must be exportable
* @param key raw key (rfc4357 6.1 CEK)
* @return  - HCRYPTKEY if success
*          - 0 if fails
*/
HCRYPTKEY get_CAPI_key_from_raw(HCRYPTPROV hProv, const unsigned char *key) {

	/// The idea is from here:  http://etutorials.org/Programming/secure+programming/Chapter+5.+Symmetric+Encryption/5.26+Creating+a+CryptoAPI+Key+Object+from+Raw+Key+Data/
	/// But GOST has a specific...
	HCRYPTKEY  resKey = 0;
	DWORD      dataLen = 0;

	// We decrement it by 4 due to 4 bytes alignment of BYTE bEncryptionParamSet[1] array.
	// @bug incompatible with x64?
	const size_t REAL_CRYPT_SIMPLEBLOB_LEN = sizeof(CRYPT_SIMPLEBLOB)
		+ sizeof(default_params) - 4;

	CRYPT_SIMPLEBLOB* keyBlob = NULL;

	keyBlob = (CRYPT_SIMPLEBLOB*)malloc(REAL_CRYPT_SIMPLEBLOB_LEN);
	if (!keyBlob) {
		HandleError("Can't allocate CRYPT_SIMPLEBLOB");
	}

	memset(keyBlob, 0, REAL_CRYPT_SIMPLEBLOB_LEN);

	fill_default_simpleblob(keyBlob);

	// key is a CEK rfc4357 6.1
	memcpy(keyBlob->bEncryptedKey, key, G28147_KEYLEN);
	memcpy(keyBlob->bEncryptionParamSet, default_params, sizeof(default_params));

	// Generate random KEK rfc4357 6.1.1.
	HCRYPTKEY kek;
	if (!CryptGenKey(hProv, CALG_G28147, CRYPT_EXPORTABLE, &kek))
	{
		HandleError("Can't generate KEK");
	}


	DWORD dparam = 0;

	dparam = ZERO_PADDING;

	if (!CryptSetKeyParam(kek, KP_PADDING, (BYTE*)&dparam, 0))
	{
		HandleError("Can't set ZERO_PADDING for generated KEK.");
	}

	/*  Well, let's assume UMK is always zeros...
	// Generate UKM rfc4357 6.1.1.
	if(!CryptGenRandom(hProvider, sizeof(keyBlob->bSV), keyBlob->bSV)){
	DBG_OUT_E("Can't generate UKM");
	goto done;
	}

	*/
	// Compute CEK_MAC rfc4357 6.1.2.
	HCRYPTKEY im_key;
	if (!CryptDuplicateKey(kek,    // from
		NULL, 0,  // two reserved
		&im_key)) // to
	{
		HandleError("Can't duplicate key for IMITO");
	}

	// Useless as UKV is always zeros, but still...
	// Set IV for IMITO
	if (!CryptSetKeyParam(
		im_key,
		KP_IV,
		keyBlob->bSV,
		0)) {
		HandleError("Can't set IV for IMITO");
	}

	HCRYPTHASH im = 0;
	if (!CryptCreateHash(hProv, CALG_G28147_IMIT, im_key, 0, &im))
	{
		HandleError("Can't create IMITO hash");
	}

	if (!CryptHashData(im, keyBlob->bEncryptedKey, G28147_KEYLEN, 0))
	{
		HandleError("Can't hash CEK");
	}

	DWORD imitLen = EXPORT_IMIT_SIZE;

	if (!CryptGetHashParam(im,
		HP_HASHVAL,
		keyBlob->bMacKey, // This is a CEK_MAC in RFC4357 6.1.2
		&imitLen, 0))
	{
		HandleError("Can't get CEK hash");
	}
	// END compute CEK_MAC


	// Encrypt key to CEK_ENC rfc4357 6.1.3.
	HCRYPTKEY enc_key;

	if (!CryptDuplicateKey(kek, 0, 0, &enc_key)) {
		HandleError("Can't dup KEK for encryption.");
	}

	dparam = CRYPT_MODE_ECB;
	if (!CryptSetKeyParam(enc_key, KP_MODE, (BYTE*)&dparam, 0)) {
		HandleError("Can't set ECB mode");
	}

	dataLen = G28147_KEYLEN;
	if (!CryptEncrypt(enc_key, 0, TRUE, 0, NULL, &dataLen, 0)) {
		HandleError("Can't detemine required buffer size.");
	}

	printf("Buffer size required: %d\n", dataLen);

	if (G28147_KEYLEN != dataLen) {
		HandleError("Required buffer size and G28147_KEYLEN mismatch");
	}

	if (!CryptEncrypt(enc_key, 0, TRUE, 0, keyBlob->bEncryptedKey, &dataLen, dataLen)) {
		HandleError("Can't encrypt raw key");
	}
	// END Encrypt key to CEK_ENC rfc4357 6.1.3.

	dparam = CALG_SIMPLE_EXPORT;
	if (!CryptSetKeyParam(kek, KP_ALGID, (BYTE *)& dparam, 0))
	{
		HandleError("Can't set SIMPLE_EXPORT param for KEK");
	}

	dataLen = REAL_CRYPT_SIMPLEBLOB_LEN;
	if (!CryptImportKey(hProv,
		(BYTE*)keyBlob,
		dataLen,
		kek,
		0,
		&resKey))
	{
		HandleError("Can't import key");
	}
	else {
		printf("Key is imported from raw value\n");
	}

done:

	if (!CryptDestroyKey(enc_key)) {
		DBG_OUT_E("Fail to destroy enc_key:");
	}

	if (!CryptDestroyKey(im_key)) {
		DBG_OUT_E("Fail to destroy im_key:");
	}

	if (!CryptDestroyKey(kek)) {
		DBG_OUT_E("Fail to destroy kek:");
	}

	free(keyBlob);
	return resKey;
}

#define GR3411LEN  64
#define BUFSIZE 1024
int main(int argc, char *argv[])
{
	HCRYPTPROV hProv;
    //Инициализация ключа
    //--------------------------------------------------------------------
	BYTE* rawKey = (BYTE*)malloc(32 * sizeof(BYTE));
    if (rawKey == NULL) {
        // Обработка ошибки выделения памяти
    }
    // Инициализация данных
    rawKey[0] = 0x2b; rawKey[1] = 0xf2; rawKey[2] = 0x26; rawKey[3] = 0xa4;
    rawKey[4] = 0xc8; rawKey[5] = 0x1f; rawKey[6] = 0x24; rawKey[7] = 0x90;
    rawKey[8] = 0xe0; rawKey[9] = 0xd9; rawKey[10] = 0x84; rawKey[11] = 0xd8;
    rawKey[12] = 0x4e; rawKey[13] = 0x57; rawKey[14] = 0xee; rawKey[15] = 0x80;
    rawKey[16] = 0x7a; rawKey[17] = 0x57; rawKey[18] = 0xc3; rawKey[19] = 0x77;
    rawKey[20] = 0xe9; rawKey[21] = 0xfa; rawKey[22] = 0x06; rawKey[23] = 0x45;
    rawKey[24] = 0x96; rawKey[25] = 0x6b; rawKey[26] = 0x9c; rawKey[27] = 0xab;
    rawKey[28] = 0x4b; rawKey[29] = 0xb3; rawKey[30] = 0x47; rawKey[31] = 0xe9;
    //--------------------------------------------------------------------

    for(int i = 0; i < 32; i++)
    {
        rawKey[i] = 0;
    }

	DWORD cbHash = 0;
    DWORD cbRead = 0;
	BYTE rgbHash[GR3411LEN];
    BYTE rgbFile[BUFSIZE];
    FILE* hFile;
	CHAR rgbDigits[] = "0123456789abcdef";

    if(!(hFile = fopen(argv[1], "r+b" )))
    {
	HandleError("Error opening input file"); 
    }
    printf( "The file %s was opened\n", argv[1]);

	if (!CryptAcquireContext(
		&hProv,
		NULL,
		NULL,
		PROV_GOST_2012_256,
		CRYPT_VERIFYCONTEXT))
	{
		HandleError("CryptAcquireContext failed");
	}
	HCRYPTKEY hmacKey = get_CAPI_key_from_raw(hProv, rawKey);

	HCRYPTHASH hHash;
	if (!CryptCreateHash(hProv, CALG_GR3411_2012_256_HMAC_FIXEDKEY, hmacKey, 0, &hHash)) {
		HandleError("CryptCreateHash failed");
	}


    cbRead = (DWORD)fread(rgbFile, 1, BUFSIZE, hFile);

    if (cbRead)
	{
	    if (!CryptHashData(hHash, rgbFile, cbRead, 0))
	    {
		CryptReleaseContext(hProv, 0);
		CryptDestroyHash(hHash);
		HandleError("CryptHashData failed");
	    }
	}

	//--------------------------------------------------------------------
	// Получение параметра объекта функции хэширования.
	cbHash = GR3411LEN;
	if (!CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
	{
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		HandleError("CryptGetHashParam failed");
	}

	printf("HMAC is: ");
	for (int i = 0; i < cbHash; i++)
	{
		printf("%c%c", rgbDigits[rgbHash[i] >> 4],
			rgbDigits[rgbHash[i] & 0xf]);
	}
	printf("\n");

	//--------------------------------------------------------------------
	// Освобождение.
	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);
    free(rawKey);
}