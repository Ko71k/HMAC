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

#include <stdio.h>
#ifdef _WIN32
#   include <windows.h>
#   include <wincrypt.h>
#else
#   include <stdlib.h>
#endif
#include "WinCryptEx.h"

static void HandleError(const char *s);

// ������ ������� (�� ������� ������� ������ �����������, �� ������������ 
// ��� �������������� ������ ������������)
//--------------------------------------------------------------------
// ������ �������� ���� �� ����������� �����. ��� ����� �������� � 
// ��������� ������ � �������� ������������ ����������.
// ���������: ��� win32 ������������� ������������ _s ������� CRT �������.
//--------------------------------------------------------------------

#define BUFSIZE 1024
#define GR3411LEN  64

int main(int argc, char *argv[])
{
    //-------------------------------------------------------------
    // ���������� � ������������� ����������. 
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    FILE* hFile;
    BYTE rgbFile[BUFSIZE];
    DWORD cbRead = 0;
    BYTE rgbHash[GR3411LEN];
    DWORD cbHash = 0;
    CHAR rgbDigits[] = "0123456789abcdef";
    DWORD i;

    //--------------------------------------------------------------------
    // �������� ����, �������� �� ��� �����.
    if(argc != 2 || argv[1] == NULL)
    {
	HandleError("The file name is absent.\n");
    }

    //--------------------------------------------------------------------
    // �������� �����.
    // if(!fopen_s(&hFile, argv[1], "r+b"))
    if(!(hFile = fopen(argv[1], "r+b" )))
    {
	HandleError("Error opening input file"); 
    }
    printf( "The file %s was opened\n", argv[1]);


    //--------------------------------------------------------------------
    // ��������� ����������� ����������������.

    if(!CryptAcquireContext(
	&hProv,
	NULL,
	NULL,
	PROV_GOST_2012_256,
	CRYPT_VERIFYCONTEXT))
    {
	HandleError("CryptAcquireContext failed");
    }

    //--------------------------------------------------------------------
    // �������� ������� ������� ������� �����������.

    if(!CryptCreateHash(hProv, CALG_GR3411_2012_256, 0, 0, &hHash))
    {
	CryptReleaseContext(hProv, 0);
	HandleError("CryptCreateHash failed"); 
    }

    //--------------------------------------------------------------------
    // ������ ������ �� ����� � ����������� ���� ������.

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

    //--------------------------------------------------------------------
    // ��������� ��������� ������� ������� �����������.
    cbHash = GR3411LEN;
    if(!CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
    {
	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);
	HandleError("CryptGetHashParam failed"); 
    }

    printf("GR3411 hash of file %s is: ", argv[1]);
    for(i = 0; i < cbHash; i++)
    {
	printf("%c%c", rgbDigits[rgbHash[i] >> 4],
	    rgbDigits[rgbHash[i] & 0xf]);
    }
    printf("\n");

    //--------------------------------------------------------------------
    // ������������.
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    fclose(hFile);

    return S_OK;
}

// ����� ������� 
// (�� ������� ������� ������ �����������, �� ������������ 
//  ��� �������������� ������ ������������)

//------------------------------------------------------------------------------
//  � ���� ������� ������������ ������� HandleError, ������� ���������
//  ������� ������, ��� ������ ��������� �� ������ � ����������� ���� 
//  ������ (stderr) � ������ �� ���������. 
//  � ����������� ���������� ��� ������� ���������� ������ ��������, 
//  ������� ������� ����� ������ ��������� �� ������.
//------------------------------------------------------------------------------
void HandleError(const char *s)
{
    DWORD err = GetLastError();
    printf("Error number     : 0x%x\n", err);
    printf("Error description: %s\n", s);
    if(!err) err = 1;
    exit(err);
}
