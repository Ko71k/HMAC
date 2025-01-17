#include <stdio.h>
#ifdef _WIN32
#   include <windows.h>
#   include <wincrypt.h>
#else
#   include <stdlib.h>
#endif
#include "WinCryptEx.h"
#define BUFSIZE 64
#define GR3411LEN  64
#define B 64 // Длина блока для алгоритма GR3411_2012_256
#define L 32 // Длина выхода хеш-функции для GR3411_2012_256

static void HandleError(const char *s);

int main(int argc, char *argv[])
{
    BYTE pbHmac[L]; // Для HMAC размером 256 бит
    DWORD dwHmacLen = sizeof(pbHmac);
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    FILE* hFile;
    FILE* keyFile;
    BYTE rgbFile[BUFSIZE];
    DWORD cbRead = 0;
    BYTE rgbHash[GR3411LEN];
    DWORD cbHash = 0;

    DWORD keyHash = 0;
    BYTE keybFile[32];
    DWORD keyRead = 0;
    CHAR rgbDigits[] = "0123456789abcdef";
    DWORD i;
    BOOL flag = 0;
    INT the72keylen;

    // Проверка того, передано ли имя файла.
    if(argc != 3 || argv[1] == NULL || argv[2] == NULL)
    {
        HandleError("Filename for data or filename for key is absent.\n");
    }

    // Открытие файла данных.
    if(!(hFile = fopen(argv[1], "r+b" )))
    {
        HandleError("Error opening input file"); 
    }
    printf( "The file %s was opened\n", argv[1]);

    // Открытие файла ключа.
    if(!(keyFile = fopen(argv[2], "r+b" )))
    {
        HandleError("Error opening input file"); 
    }
    printf( "The file %s was opened\n", argv[2]);

    // Получение дескриптора криптопровайдера.
    if(!CryptAcquireContext(&hProv, NULL, NULL, PROV_GOST_2012_256, CRYPT_VERIFYCONTEXT))
    {
        HandleError("CryptAcquireContext failed");
    }

    // Создание нового пустого объекта функции хэширования ключа (в случае, если длина ключа > 256 бит).
    if(!CryptCreateHash(hProv, CALG_GR3411_2012_256, 0, 0, &hHash))
    {
        CryptReleaseContext(hProv, 0);
        HandleError("CryptCreateHash failed"); 
    }

    // Чтение данных из файла ключа и хэширование этих данных.
    keyRead = (DWORD)fread(keybFile, 1, 32, keyFile);
    the72keylen = keyRead;
    if (the72keylen > 32)
    {
    flag = 1;
    do
    {
        keyRead = (DWORD)fread(keybFile, 1, 32, keyFile);
        
            if (!CryptHashData(hHash, keybFile, keyRead, 0))
            {
                CryptReleaseContext(hProv, 0);
                CryptDestroyHash(hHash);
                HandleError("CryptHashData failed");
            }
        }
    while(!feof(keyFile));
    }
    // Получение хэша.
    keyHash = 32;
    if(!CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &keyHash, 0))
    {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        HandleError("CryptGetHashParam failed"); 
    }
    // Уничтожение текущего хэша для создания нового с opad.
    
    printf("key HMAC is: ");
    for(i = 0; i < keyHash; i++)
    {
        printf("%c%c", rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i] & 0xf]);
    }
    printf("\n");

    CryptDestroyHash(hHash);


    // Инициализация ключа
    BYTE pbKey[64] = { /* Ваш ключ K */ };

    if (flag)
    {
        for(i = 0; i < 32; i++)
        {
            pbKey[i] = rgbHash[i];
            //printf("%c%c", rgbDigits[pbKey[i] >> 4], rgbDigits[pbKey[i] & 0xf]);
        }
    }
    else
    {
        for(i = 0; i < the72keylen; i++)
        {
            pbKey[i] = keybFile[i];
            printf("%c%c", rgbDigits[keybFile[i] >> 4], rgbDigits[keybFile[i] & 0xf]);
        }
        printf("\n");
    }
    for(i = 32; i < 64; i++)
    {
        pbKey[i] = 0x0;
    }
    printf("Final key is: ");
    for(i = 0; i < 64; i++)
    {
        printf("%c%c", rgbDigits[pbKey[i] >> 4], rgbDigits[pbKey[i] & 0xf]);
    }
    printf("\n");
    BYTE ipad[B], opad[B];
    BYTE KxorIpad[B], KxorOpad[B];



    // Инициализация ipad и opad
    for(i = 0; i < B; i++) {
        ipad[i] = 0x36;
        opad[i] = 0x5C;
    }

    // XOR ключа K с ipad и opad
    for(i = 0; i < B; i++) {
        KxorIpad[i] = pbKey[i] ^ ipad[i];
        KxorOpad[i] = pbKey[i] ^ opad[i];
    }


    

    // Создание пустого объекта функции хэширования для ipad.
    if(!CryptCreateHash(hProv, CALG_GR3411_2012_256, 0, 0, &hHash))
    {
        CryptReleaseContext(hProv, 0);
        HandleError("CryptCreateHash failed"); 
    }

    // Хэширование KxorIpad.
    if (!CryptHashData(hHash, KxorIpad, B, 0))
    {
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        HandleError("CryptHashData failed");
    }

    // Чтение данных из файла и хэширование этих данных вместе с KxorIpad.
    do
    {
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
    }
    while(!feof(hFile));

    // Получение хэша.
    cbHash = GR3411LEN;
    if(!CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
    {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        HandleError("CryptGetHashParam failed"); 
    }

    // Уничтожение текущего хэша для создания нового с opad.
    CryptDestroyHash(hHash);

    // Создание нового пустого объекта функции хэширования для opad.
    if(!CryptCreateHash(hProv, CALG_GR3411_2012_256, 0, 0, &hHash))
    {
        CryptReleaseContext(hProv, 0);
        HandleError("CryptCreateHash failed"); 
    }

    // Хэширование KxorOpad.
    if (!CryptHashData(hHash, KxorOpad, B, 0))
    {
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        HandleError("CryptHashData failed");
    }

     // Хэширование предыдущего хэша вместе с KxorOpad.
    if (!CryptHashData(hHash, rgbHash, cbHash, 0))
    {
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        HandleError("CryptHashData failed");
    }

    // Получение окончательного HMAC.
    if(!CryptGetHashParam(hHash, HP_HASHVAL, pbHmac, &dwHmacLen, 0))
    {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        HandleError("CryptGetHashParam failed"); 
    }

    printf("HMAC is: ");
    for(i = 0; i < dwHmacLen; i++)
    {
        printf("%c%c", rgbDigits[pbHmac[i] >> 4], rgbDigits[pbHmac[i] & 0xf]);
    }
    printf("\n");

    // Освобождение ресурсов.
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    fclose(hFile);

    return 0;
}
void HandleError(const char *s)
{
    DWORD err = GetLastError();
    printf("Error number     : 0x%x\n", err);
    printf("Error description: %s\n", s);
    if(!err) err = 1;
    exit(err);
}
