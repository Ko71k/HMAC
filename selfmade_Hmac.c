#include <stdio.h>
#ifdef _WIN32
#   include <windows.h>
#   include <wincrypt.h>
#else
#   include <stdlib.h>
#endif
#include "WinCryptEx.h"
#define BUFSIZE 1024
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
    BYTE rgbFile[BUFSIZE];
    DWORD cbRead = 0;
    BYTE rgbHash[GR3411LEN];
    DWORD cbHash = 0;
    CHAR rgbDigits[] = "0123456789abcdef";
    DWORD i;

    // Инициализация ключа
    BYTE pbKey[B] = { /* Ваш ключ K */ };
    for(i = 0; i < 64; i++)
    {
        pbKey[i] = 1;
    }
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

    // Проверка того, передано ли имя файла.
    if(argc != 2 || argv[1] == NULL)
    {
        HandleError("The file name is absent.\n");
    }

    // Открытие файла.
    if(!(hFile = fopen(argv[1], "r+b" )))
    {
        HandleError("Error opening input file"); 
    }
    printf( "The file %s was opened\n", argv[1]);

    // Получение дескриптора криптопровайдера.
    if(!CryptAcquireContext(&hProv, NULL, NULL, PROV_GOST_2012_256, CRYPT_VERIFYCONTEXT))
    {
        HandleError("CryptAcquireContext failed");
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

    printf("HMAC of file %s is: ", argv[1]);
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
