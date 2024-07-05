/* vim:set sw=4 ts=8 fileencoding=cp1251::Кодировка:WINDOWS-1251[АБЁЪЯабёъя] */
#ifdef _WIN32
    #pragma setlocale("rus")
#endif
/*
 * Copyright (c) 2000, компания Крипто-Про
 * 
 * Разрешается повторное распространение и использование как в виде исходного
 * кода, так и в двоичной форме, с изменениями или без, при соблюдении
 * следующих условий:
 * 
 * 1) При повторном распространении исходного кода должно оставаться 
 *    указанное выше уведомление об авторском праве, этот список условий 
 *    и последующий отказ от гарантий.
 * 
 * 2) При повторном распространении двоичного кода должно сохраняться
 *    указанная выше информация об авторском праве, этот список условий
 *    и последующий отказ от гарантий в документации и/или в других материалах,
 *    поставляемых при распространении.
 * 
 * ЭТА ПРОГРАММА ПРЕДОСТАВЛЕНА БЕСПЛАТНО ВЛАДЕЛЬЦАМИ АВТОРСКИХ ПРАВ И/ИЛИ
 * ДРУГИМИ СТОРОНАМИ "КАК ОНА ЕСТЬ" БЕЗ КАКОГО-ЛИБО ВИДА ГАРАНТИЙ, ВЫРАЖЕННЫХ
 * ЯВНО ИЛИ ПОДРАЗУМЕВАЕМЫХ, ВКЛЮЧАЯ, НО НЕ ОГРАНИЧИВАЯСЬ ИМИ, ПОДРАЗУМЕВАЕМЫЕ
 * ГАРАНТИИ КОММЕРЧЕСКОЙ ЦЕННОСТИ И ПРИГОДНОСТИ ДЛЯ КОНКРЕТНОЙ ЦЕЛИ. НИ В КОЕМ
 * СЛУЧАЕ, ЕСЛИ НЕ ТРЕБУЕТСЯ СООТВЕТСТВУЮЩИМ ЗАКОНОМ, ИЛИ НЕ УСТАНОВЛЕНО В
 * УСТНОЙ ФОРМЕ, НИ ОДИН ВЛАДЕЛЕЦ АВТОРСКИХ ПРАВ И НИ ОДНО ДРУГОЕ ЛИЦО, КОТОРОЕ
 * МОЖЕТ ИЗМЕНЯТЬ И/ИЛИ ПОВТОРНО РАСПРОСТРАНЯТЬ ПРОГРАММУ, КАК БЫЛО СКАЗАНО
 * ВЫШЕ, НЕ НЕСЁТ ОТВЕТСТВЕННОСТИ, ВКЛЮЧАЯ ЛЮБЫЕ ОБЩИЕ, СЛУЧАЙНЫЕ, СПЕЦИАЛЬНЫЕ
 * ИЛИ ПОСЛЕДОВАВШИЕ УБЫТКИ, В СЛЕДСТВИИ ИСПОЛЬЗОВАНИЯ ИЛИ НЕВОЗМОЖНОСТИ
 * ИСПОЛЬЗОВАНИЯ ПРОГРАММЫ (ВКЛЮЧАЯ, НО НЕ ОГРАНИЧИВАЯСЬ ПОТЕРЕЙ ДАННЫХ,
 * ИЛИ ДАННЫМИ, СТАВШИМИ НЕПРАВИЛЬНЫМИ, ИЛИ ПОТЕРЯМИ ПРИНЕСЕННЫМИ ИЗ-ЗА ВАС ИЛИ
 * ТРЕТЬИХ ЛИЦ, ИЛИ ОТКАЗОМ ПРОГРАММЫ РАБОТАТЬ СОВМЕСТНО С ДРУГИМИ ПРОГРАММАМИ),
 * ДАЖЕ ЕСЛИ ТАКОЙ ВЛАДЕЛЕЦ ИЛИ ДРУГОЕ ЛИЦО БЫЛИ ИЗВЕЩЕНЫ О ВОЗМОЖНОСТИ
 * ТАКИХ УБЫТКОВ.
 * 
 * Copyright (c) 2000, Crypto-Pro Company All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1) Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 
 * 2) Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

/*!
 * \brief CryptoPro CSP WinCrypt.h extensions
 */

#ifndef _WINCRYPTEX_H_INCLUDED
#define _WINCRYPTEX_H_INCLUDED

#ifndef _WINCRYPTEX_USE_EXTERNAL_TYPES

#  ifndef HAVE_CONFIG_H
#    ifdef __APPLE__
#      ifndef UNIX
#        define UNIX
#      endif /*UNIX*/
#      ifndef SIZEOF_VOID_P
#        ifdef __LP64__
#          define SIZEOF_VOID_P 8
#        else /*__LP64__*/
#          define SIZEOF_VOID_P 4
#        endif /*__LP64__*/
#      endif /*SIZEOF_VOID_P*/
#    endif /*__APPLE__*/
#  endif 

#  if defined UNIX || defined CSP_LITE
#    include "CSP_WinCrypt.h"
#  else // UNIX
#    if !defined _WINDOWS_
#        define WIN32_LEAN_AND_MEAN // Для ускорения компиляции
#        include <windows.h>
#    endif // _WINDOWS_
#    include <wincrypt.h>
#  endif // UNIX

#endif // _WINCRYPTEX_USE_EXTERNAL_TYPES

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

// CSP 1.1
#define CP_DEF_PROV_A "Crypto-Pro Cryptographic Service Provider"
#define CP_DEF_PROV_W L"Crypto-Pro Cryptographic Service Provider"
#ifdef UNICODE
#define CP_DEF_PROV CP_DEF_PROV_W
#else //!UNICODE
#define CP_DEF_PROV CP_DEF_PROV_A
#endif //!UNICODE

// CSP 2.0
#define CP_GR3410_94_PROV_A "Crypto-Pro GOST R 34.10-94 Cryptographic Service Provider"
#define CP_GR3410_94_PROV_W L"Crypto-Pro GOST R 34.10-94 Cryptographic Service Provider"
#ifdef UNICODE
#define CP_GR3410_94_PROV CP_GR3410_94_PROV_W
#else //!UNICODE
#define CP_GR3410_94_PROV CP_GR3410_94_PROV_A
#endif //!UNICODE

#define CP_GR3410_2001_PROV_A "Crypto-Pro GOST R 34.10-2001 Cryptographic Service Provider"
#define CP_GR3410_2001_PROV_W L"Crypto-Pro GOST R 34.10-2001 Cryptographic Service Provider"
#ifdef UNICODE
#define CP_GR3410_2001_PROV CP_GR3410_2001_PROV_W
#else //!UNICODE
#define CP_GR3410_2001_PROV CP_GR3410_2001_PROV_A
#endif //!UNICODE

#define CP_GR3410_2012_PROV_A "Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider"
#ifdef UNICODE
#define CP_GR3410_2012_PROV CAT_L(CP_GR3410_2012_PROV_A)
#else //!UNICODE
#define CP_GR3410_2012_PROV CP_GR3410_2012_PROV_A
#endif //!UNICODE

#define CP_GR3410_2012_STRONG_PROV_A "Crypto-Pro GOST R 34.10-2012 Strong Cryptographic Service Provider"
#ifdef UNICODE
#define CP_GR3410_2012_STRONG_PROV CAT_L(CP_GR3410_2012_STRONG_PROV_A)
#else //!UNICODE
#define CP_GR3410_2012_STRONG_PROV CP_GR3410_2012_STRONG_PROV_A
#endif //!UNICODE

#define CP_RSA_AES_ENH_PROV_A "Crypto-Pro Enhanced RSA and AES CSP"
#ifdef UNICODE
#define CP_RSA_AES_ENH_PROV CAT_L(CP_RSA_AES_ENH_PROV_A)
#else //!UNICODE
#define CP_RSA_AES_ENH_PROV CP_RSA_AES_ENH_PROV_A
#endif //!UNICODE

#define CP_ECDSA_AES_PROV_A "Crypto-Pro ECDSA and AES CSP"
#ifdef UNICODE
#define CP_ECDSA_AES_PROV CAT_L(CP_ECDSA_AES_PROV_A)
#else //!UNICODE
#define CP_ECDSA_AES_PROV CP_ECDSA_AES_PROV_A
#endif //!UNICODE

#define CP_RSA_BASE_PROV_A "Crypto-Pro RSA Cryptographic Service Provider"
#ifdef UNICODE
#define CP_RSA_BASE_PROV CAT_L(CP_RSA_BASE_PROV_A)
#else //!UNICODE
#define CP_RSA_BASE_PROV CP_RSA_BASE_PROV_A
#endif //!UNICODE

#define CP_EC_CURVE25519_PROV_A "Crypto-Pro Curve25519 and AES CSP"
#ifdef UNICODE
#define CP_EC_CURVE25519_PROV CAT_L(CP_EC_CURVE25519_PROV_A)
#else //!UNICODE
#define CP_EC_CURVE25519_PROV CP_EC_CURVE25519_PROV_A
#endif //!UNICODE

#define CP_KC1_GR3410_94_PROV_A "Crypto-Pro GOST R 34.10-94 KC1 CSP"
#define CP_KC1_GR3410_94_PROV_W L"Crypto-Pro GOST R 34.10-94 KC1 CSP"
#ifdef UNICODE
#define CP_KC1_GR3410_94_PROV CP_KC1_GR3410_94_PROV_W
#else //!UNICODE
#define CP_KC1_GR3410_94_PROV CP_KC1_GR3410_94_PROV_A
#endif //!UNICODE

#define CP_KC1_GR3410_2001_PROV_A "Crypto-Pro GOST R 34.10-2001 KC1 CSP"
#define CP_KC1_GR3410_2001_PROV_W L"Crypto-Pro GOST R 34.10-2001 KC1 CSP"
#ifdef UNICODE
#define CP_KC1_GR3410_2001_PROV CP_KC1_GR3410_2001_PROV_W
#else //!UNICODE
#define CP_KC1_GR3410_2001_PROV CP_KC1_GR3410_2001_PROV_A
#endif //!UNICODE

#define CP_KC1_GR3410_2012_PROV_A "Crypto-Pro GOST R 34.10-2012 KC1 CSP"
#ifdef UNICODE
#define CP_KC1_GR3410_2012_PROV CAT_L(CP_KC1_GR3410_2012_PROV_A)
#else //!UNICODE
#define CP_KC1_GR3410_2012_PROV CP_KC1_GR3410_2012_PROV_A
#endif //!UNICODE

#define CP_KC1_GR3410_2012_STRONG_PROV_A "Crypto-Pro GOST R 34.10-2012 KC1 Strong CSP"
#ifdef UNICODE
#define CP_KC1_GR3410_2012_STRONG_PROV CAT_L(CP_KC1_GR3410_2012_STRONG_PROV_A)
#else //!UNICODE
#define CP_KC1_GR3410_2012_STRONG_PROV CP_KC1_GR3410_2012_STRONG_PROV_A
#endif //!UNICODE

#define CP_KC2_GR3410_94_PROV_A "Crypto-Pro GOST R 34.10-94 KC2 CSP"
#define CP_KC2_GR3410_94_PROV_W L"Crypto-Pro GOST R 34.10-94 KC2 CSP"
#ifdef UNICODE
#define CP_KC2_GR3410_94_PROV CP_KC2_GR3410_94_PROV_W
#else //!UNICODE
#define CP_KC2_GR3410_94_PROV CP_KC2_GR3410_94_PROV_A
#endif //!UNICODE

#define CP_KC2_GR3410_2001_PROV_A "Crypto-Pro GOST R 34.10-2001 KC2 CSP"
#define CP_KC2_GR3410_2001_PROV_W L"Crypto-Pro GOST R 34.10-2001 KC2 CSP"
#ifdef UNICODE
#define CP_KC2_GR3410_2001_PROV CP_KC2_GR3410_2001_PROV_W
#else //!UNICODE
#define CP_KC2_GR3410_2001_PROV CP_KC2_GR3410_2001_PROV_A
#endif //!UNICODE

#define CP_KC2_GR3410_2012_PROV_A "Crypto-Pro GOST R 34.10-2012 KC2 CSP"
#ifdef UNICODE
#define CP_KC2_GR3410_2012_PROV CAT_L(CP_KC2_GR3410_2012_PROV_A)
#else //!UNICODE
#define CP_KC2_GR3410_2012_PROV CP_KC2_GR3410_2012_PROV_A
#endif //!UNICODE

#define CP_KC2_GR3410_2012_STRONG_PROV_A "Crypto-Pro GOST R 34.10-2012 KC2 Strong CSP"
#ifdef UNICODE
#define CP_KC2_GR3410_2012_STRONG_PROV CAT_L(CP_KC2_GR3410_2012_STRONG_PROV_A)
#else //!UNICODE
#define CP_KC2_GR3410_2012_STRONG_PROV CP_KC2_GR3410_2012_STRONG_PROV_A
#endif //!UNICODE

#define PH_GR3410_2001_PROV_A "Phoenix-CS GOST R 34.10-2001 Cryptographic Service Provider"
#define PH_GR3410_2001_PROV_W L"Phoenix-CS GOST R 34.10-2001 Cryptographic Service Provider"
#ifdef UNICODE
#define PH_GR3410_2001_PROV PH_GR3410_2001_PROV_W
#else //!UNICODE
#define PH_GR3410_2001_PROV PH_GR3410_2001_PROV_A
#endif //!UNICODE

#ifdef _WIN32
#  define CP_KC1_GR3410_2001_MAGISTRA_PROV_A "GOST R 34.10-2001 Magistra CSP"
#  define CP_KC1_GR3410_2001_MAGISTRA_PROV_W L"GOST R 34.10-2001 Magistra CSP"
#  define CP_KC1_GR3410_2001_RUTOKEN_PROV_A "GOST R 34.10-2001 Rutoken CSP"
#  define CP_KC1_GR3410_2001_RUTOKEN_PROV_W L"GOST R 34.10-2001 Rutoken CSP"
#  define CP_KC1_GR3410_2001_ETOKEN_PROV_A "GOST R 34.10-2001 eToken CSP"
#  define CP_KC1_GR3410_2001_ETOKEN_PROV_W L"GOST R 34.10-2001 eToken CSP"
#  define CP_KC1_GR3410_2001_ETOKENGOST_PROV_A "GOST R 34.10-2001 eToken GOST CSP"
#  define CP_KC1_GR3410_2001_ETOKENGOST_PROV_W L"GOST R 34.10-2001 eToken GOST CSP"
#  define CP_KC1_GR3410_2001_UECFK_PROV_A "CryptoPro GOST R 34.10-2001 UEC CSP"
#  define CP_KC1_GR3410_2001_UECFK_PROV_W L"CryptoPro GOST R 34.10-2001 UEC CSP"
#else
#  define CP_KC1_GR3410_2001_MAGISTRA_PROV_A "Crypto-Pro GOST R 34.10-2001 FKC CSP"
#  define CP_KC1_GR3410_2001_MAGISTRA_PROV_W L"Crypto-Pro GOST R 34.10-2001 FKC CSP"
#  define CP_KC1_GR3410_2001_RUTOKEN_PROV_A "Crypto-Pro GOST R 34.10-2001 FKC CSP"
#  define CP_KC1_GR3410_2001_RUTOKEN_PROV_W L"Crypto-Pro GOST R 34.10-2001 FKC CSP"
#  define CP_KC1_GR3410_2001_ETOKEN_PROV_A "Crypto-Pro GOST R 34.10-2001 FKC CSP"
#  define CP_KC1_GR3410_2001_ETOKEN_PROV_W L"Crypto-Pro GOST R 34.10-2001 FKC CSP"
#  define CP_KC1_GR3410_2001_ETOKENGOST_PROV_A "Crypto-Pro GOST R 34.10-2001 FKC CSP"
#  define CP_KC1_GR3410_2001_ETOKENGOST_PROV_W L"Crypto-Pro GOST R 34.10-2001 FKC CSP"
#  define CP_KC1_GR3410_2001_UECFK_PROV_A "Crypto-Pro GOST R 34.10-2001 FKC CSP"
#  define CP_KC1_GR3410_2001_UECFK_PROV_W L"Crypto-Pro GOST R 34.10-2001 FKC CSP"
#endif

#ifdef UNICODE
#define CP_KC1_GR3410_2001_MAGISTRA_PROV CP_KC1_GR3410_2001_MAGISTRA_PROV_W
#define CP_KC1_GR3410_2001_RUTOKEN_PROV CP_KC1_GR3410_2001_RUTOKEN_PROV_W
#define CP_KC1_GR3410_2001_ETOKEN_PROV CP_KC1_GR3410_2001_ETOKEN_PROV_W
#define CP_KC1_GR3410_2001_ETOKENGOST_PROV CP_KC1_GR3410_2001_ETOKENGOST_PROV_W
#define CP_KC1_GR3410_2001_UECFK_PROV CP_KC1_GR3410_2001_UECFK_PROV_W
#else //!UNICODE
#define CP_KC1_GR3410_2001_MAGISTRA_PROV CP_KC1_GR3410_2001_MAGISTRA_PROV_A
#define CP_KC1_GR3410_2001_RUTOKEN_PROV CP_KC1_GR3410_2001_RUTOKEN_PROV_A
#define CP_KC1_GR3410_2001_ETOKEN_PROV CP_KC1_GR3410_2001_ETOKEN_PROV_A
#define CP_KC1_GR3410_2001_ETOKENGOST_PROV CP_KC1_GR3410_2001_ETOKENGOST_PROV_A
#define CP_KC1_GR3410_2001_UECFK_PROV CP_KC1_GR3410_2001_UECFK_PROV_A
#endif //!UNICODE

#define CP_KC1_GR3410_2001_FLASH_PROV_A "Crypto-Pro Flash Drive KC1 CSP"
#define CP_KC1_GR3410_2001_FLASH_PROV_W L"Crypto-Pro Flash Drive KC1 CSP"
#ifdef UNICODE
#define CP_KC1_GR3410_2001_FLASH_PROV CP_KC1_GR3410_2001_FLASH_PROV_W
#else //!UNICODE
#define CP_KC1_GR3410_2001_FLASH_PROV CP_KC1_GR3410_2001_FLASH_PROV_A
#endif //!UNICODE

#define CP_KC1_GR3410_2001_REGISTRY_PROV_A "Crypto-Pro Registry KC1 CSP"
#define CP_KC1_GR3410_2001_REGISTRY_PROV_W L"Crypto-Pro Registry KC1 CSP"
#ifdef UNICODE
#define CP_KC1_GR3410_2001_REGISTRY_PROV CP_KC1_GR3410_2001_REGISTRY_PROV_W
#else //!UNICODE
#define CP_KC1_GR3410_2001_REGISTRY_PROV CP_KC1_GR3410_2001_REGISTRY_PROV_A
#endif //!UNICODE

#ifdef UNICODE
#define CP_CERT_STORE_PROV_FILENAME_T CERT_STORE_PROV_FILENAME_W
#else //!UNICODE
#define CP_CERT_STORE_PROV_FILENAME_T CERT_STORE_PROV_FILENAME_A
#endif //!UNICODE

#define CRYPTOPRO_TRUSTED_CERT_STORE_NAME_A "CryptoProTrustedStore"
#define CRYPTOPRO_TRUSTED_CERT_STORE_NAME_W L"CryptoProTrustedStore"

#ifndef UNIX 
#define PROV_TYPE_CNG ((DWORD)(-1))
#endif // !UNIX

/*
 * PROV_GOST_DH == 2 == PROV_RSA_SIG
 */
#define PROV_GOST_DH 2		//deprecated

/*
 * На 09.07.01 в Platform SDK последний зарегистрированный
 * CSP - PROV_RSA_AES == 24
 *
 * Я выбрал для  PROV_GOST_* два случайных числа из диапазона [53..89]
 *
 * Randomly selected numbers from [53..89]
 */
#define PROV_GOST_94_DH 71	//deprecated
#define PROV_GOST_2001_DH 75
#define PROV_GOST_2012_256 80
#define PROV_GOST_2012_512 81

#ifndef PROV_RSA_AES
#define PROV_RSA_AES 24
#endif /*PROV_RSA_AES*/
#define PROV_EC_CURVE25519 32

/* Типы контейнера */
/* Container Types */
#define KEY_CARRIER_VERSION_V1 1 /* не поддерживается с 3 марта 2020 года */
#define KEY_CARRIER_VERSION_V2 2
#define KEY_CARRIER_VERSION_V3 3 /* FKC-1. unused in 5.0 */
#define KEY_CARRIER_VERSION_V4 4 /* FKC-2. */

/* Дополнительные типы кодирования.
 * В Platform SDK определены только CRYPT_ASN_ENCODING (1),
 * CRYPT_NDR_ENCODING (2) и значения выше 0x10000 (PKCS7). 
 *
 * Additional Encoding Types
 */
#define CRYPT_XER_ENCODING (8)

/* Дополнительные свойства контекстов сертификатов */
/* CRYPT_DATA_BLOB, содержащий отпечаток shadow-сертификата, который должен быть использован для создания Schannel Credential */
#define CP_CERT_SHADOW_CERT_PROP_ID		0x0000FF00
/* CRYPT_DATA_BLOB, содержащий отпечаток сертификата, который должен быть использован для создания серверного удостоверения с несколькими сертификатами в IIS [http.sys]*/
#define CP_CERT_LINKED_CERT_PROP_ID		0x0000FF01

#define CERT_URL_OBJECT_CACHE_DATA_PROP_ID	0x00008001

/* 
 * Дополнительные флаги AcquireContext. Глобальные установки криптопровайдера.
 *
 * Addional AcquireContext flags. Global cryptoprovider settings.
 */
#define CRYPT_GENERAL				0x00004000
#define CRYPT_NOSERIALIZE			0x00010000 // from 3.6.5327, before: 0x8000 [
#define CRYPT_REBOOT				0x00020000
#define CRYPT_PROMT_INSERT_MEDIA		0x00040000 // supported from 3.6.5360
#define CRYPT_UECDATACONTEXT			0x00080000
#define CRYPT_CMS_HIGHLOAD_NOSERIALIZE		0x00100000
#define CRYPT_LOCAL_PASSWORD_CACHE              0x00200000
#define CRYPT_NO_CONTAINER_CACHE                0x00400000

#define ACQUIRE_CONTEXT_SUPPORTED_FLAGS		(CRYPT_GENERAL | CRYPT_NOSERIALIZE | CRYPT_REBOOT | CRYPT_PROMT_INSERT_MEDIA | CRYPT_UECDATACONTEXT | CRYPT_CMS_HIGHLOAD_NOSERIALIZE | CRYPT_NO_CONTAINER_CACHE | CRYPT_LOCAL_PASSWORD_CACHE)

/* 
 * Дополнительные флаги PFXImportCertStore
 *
 * Addional PFXImportCertStore flags
 */
#ifndef PKCS12_IMPORT_SILENT
    #define PKCS12_IMPORT_SILENT                0x00000040
#endif

#ifndef CRYPT_USER_PROTECTED_STRONG
    #define CRYPT_USER_PROTECTED_STRONG         0x00100000
#endif

/* 
 * Дополнительные флаги PFXExportCertStoreEx
 *
 * Addional PFXExportCertStoreEx flags
 */
#ifndef PKCS12_PROTECT_TO_DOMAIN_SIDS
    #define PKCS12_PROTECT_TO_DOMAIN_SIDS           0x0020
#endif
#ifndef PKCS12_EXPORT_SILENT
    #define PKCS12_EXPORT_SILENT                    0x0040
#endif

#define szOID_PKCS_12_pbeWithGostR3411_94_AndGost28147_89_CryptoPro_A_ParamSet        "1.2.840.113549.1.12.1.80"

#define szOID_PKCS_5_PBES2			    "1.2.840.113549.1.5.13"

/*
 * Флаги CryptSetProvParam
 *
 * CryptSetProvParam flags
 */

/* флаг для запоминания пароля в реестре */
#define CP_CRYPT_SAVE_PASSWORD 0x00001000

/* Флаг, указывающий, что запрошенная функциональность будет применена 
 * только к текущему контексту провайдера */
#define CP_CRYPT_CACHE_ONLY 0x00002000

/* Синоним CP_CRYPT_CACHE_ONLY. Указывает, что запрошенная функциональность будет применена
 * только к текущему контексту контейнера */
#define CP_CRYPT_CONTAINER_ONLY CP_CRYPT_CACHE_ONLY

 /* Флаг, указывающий, что из PP_USER_CERTSTORE/PP_ROOT_CERTSTORE
 * будет возвращено сериализованное store в виде блоба. 
 * Также флаг применим для CryptSetProvParam(PP_ROOT_CERTSTORE)
 */
#define CP_CRYPT_SERIALIZED_STORE 0x00004000

/* Дополнительные флаги CryptMsgOpenToEncode и CryptMsgControl, определяющие
 * поведение при формировании подписи CAdES-BES. */
#define CPCMSG_CADES_STRICT		    (0x00000100)
#define CPCMSG_CADES_DISABLE                (0x00000200)
#define CPCMSG_CADES_DISABLE_CERT_SEARCH    (0x00000400)

/* Дополнительные флаги CryptMsgOpenToEncode, CryptMsgUpdate, CryptMsgControl,
 * определяющие какие данные (контент/атрибуты) будут хэшироваться 
 * на pin-pad/SafeTouch. */
#define CPCMSG_DTBS_CONTENT                 (0x00000800)
#define CPCMSG_DTBS_ATTRIBUTE               (0x00001000)
#define CPCMSG_DTBS_CERTIFICATE             (0x00002000)

/* Дополнительные флаги CryptSignMessage, определяющие
 * поведение при формировании подписи CAdES-BES. */
#define CPCRYPT_MESSAGE_CADES_STRICT	    (CPCMSG_CADES_STRICT)
#define CPCRYPT_MESSAGE_CADES_DISABLE	    (CPCMSG_CADES_DISABLE)

/* Дополнительные флаги CryptSignMessage, определяющие
 * какие данные (контент/атрибуты) будут хэшироваться 
 * на pin-pad/SafeTouch. */
#define CPCRYPT_MESSAGE_DTBS_CONTENT	    (CPCMSG_DTBS_CONTENT)
#define CPCRYPT_MESSAGE_DTBS_ATTRIBUTE	    (CPCMSG_DTBS_ATTRIBUTE)

/* ???? Флаг CryptGenKey, определяющий ключи, используемые совместно с ФКН.*/
#define CRYPT_ECCNEGATIVE	0x00000400 
#define CRYPT_PUBLICCOMPRESS	0x00000800 

/* флаги CryptSetKeyParam KP_ADDX для сложения/вычитания */
#define EC_PLUS 0
#define EC_MINUS 1

/* флаг CryptSetKeyParam KP_AUTH_TAG для сохранения в контексте ключа тэга аутентификации сообщения */
#define SAVE_AUTH_TAG		0x100

/* флаг GenKey для разрешения/запрета ДХ для ключей подписи (переопределяем CRYPT_SGCKEY) */
#define	CP_CRYPT_DH_ALLOWED        0x00002000

/* флаг KP_PERMISSIONS для разрешения/запрета ДХ */
#define CP_CRYPT_DH_PERMISSION	0x00010000

/* флаг KP_STORE, указывающий, что записываемый в контейнер ключ может быть перезаписан другим вызовом KP_STORE */
#define CP_CRYPT_REWRITABLE 0x00020000

/* флаг для определения наследования ключом согласования экспортируемости исходного секретного ключа */
#define CRYPT_KEY_PROTECTION_HIGH 0x00400000

/* флаг принудительного вычисления открытого ключа при экспорте */
#define CP_CRYPT_CALCULATE_PUBLIC_KEY	(0x80)

/* флаг ImportKey для ускорения повторного использования импортируемого открытого ключа */
#define	CP_PUBKEY_REUSABLE        0x00002000

/* флаг создания CALG_TLS1_MASTER при выполнении ECDHE */
#define CP_CREATE_TLS_PREMASTER	  0x00004000

/* флаг форсирования Diffie-Hellman */
#define CP_FORCE_GOST_DH	  0x00008000

 /* Флаг, указывающий, что при экспорте/импорте pfx
 * необходимо попытаться установить/извлечь срок действия контейнера
 * в атрибуты. Используется в функциях CryptExportKey и CryptImportKey.
 */
#define CP_CRYPT_PKUP_ATTRIBUTE 0x00800000

/* флаг SetKeyParam для умножения эллиптики на хэндл */
#define CP_CRYPT_DATA_HANDLE	  0x00000010

/* флаг SetKeyParam для экспортируемости результата KP_ADDX */
#define CP_MAKE_EXPORTABLE	  0x00000020

/* Флаг предназначен для работы с ImportKey и ExportKey только с использованием Diffie-Hellman.
   Обеспечивает работу с блобом без ASN.1 структуры с информацией об открытом ключе. */
#define CP_PRIMITIVE_PUBLICKEYBLOB 0x00000020

/* Флаг предназначен для работы ExportKey и ImportKey при экспорте/импорте симметричных ключей в MGM (CALG_MGM_EXPORT_M/K).
   Отключает вычисление и проверку тэга аутентификации. */
#define CP_AUTH_TAG_DISABLED	   0x10000000

/* Дополнительные режимы дополнения блока открытого текста до кратности размера блока шифрования*/
#define ISO10126_PADDING 4
#define ANSI_X923_PADDING 5
#define TLS_1_0_PADDING 6
#define ISO_IEC_7816_4_PADDING 7

#define TLS_1_0_MAX_PADDING_LENGTH 256
#define MAX_PADDING_LENGTH TLS_1_0_MAX_PADDING_LENGTH

/* Описатели пользовательских ключей */
#define USERKEY_KEYEXCHANGE			AT_KEYEXCHANGE
#define USERKEY_SIGNATURE			AT_SIGNATURE

#define CP_DISREGARD_STRENGTHENED_KEY_USAGE_CONTROL	(0x80000000)

/* флаги SignHash\VerifySignature */
#define CP_ECC_PLAIN_SIGNATURE				(0x00000008) // формат подписи (r|s) в LittleEndian
#define CP_CONTANER_AFFECTED_SIGNATURE			(0x00000010)
#define CP_ECC_PLAIN_SIGNATURE_CNG_REVERSED		(0x00000020) // формат подписи (s|r) в LittleEndian
#define CP_PSEUDO_RANDOM_K_ONLY				(0x00000040) // отключает новый формат выработки k
#define CRYPT_RSA_PSS					(0x00000080) // подпись с PSS-паддингом

#define CMS_BLOCKLEN_TAG			'B'

/* Algorithm types */
#define ALG_TYPE_GR3410				(7 << 9)
#define ALG_TYPE_SHAREDKEY			(8 << 9)
/* GR3411 sub-ids */
#define ALG_SID_GR3411				30
#define ALG_SID_GR3411_HASH			39
#define ALG_SID_GR3411_HASH34			40
#define	ALG_SID_GR3411_HMAC_FIXEDKEY		55
#define ALG_SID_UECMASTER_DIVERS		47
#define ALG_SID_SHAREDKEY_HASH			50
#define ALG_SID_FITTINGKEY_HASH			51
/* G28147 sub_ids */
#define ALG_SID_G28147				30
#define ALG_SID_PRODIVERS			38
#define ALG_SID_RIC1DIVERS			40
#define ALG_SID_PRO12DIVERS			45
#define ALG_SID_KDF_TREE_GOSTR3411_2012_256	35
/* Export Key sub_id */
#define ALG_SID_PRO_EXP				31
#define ALG_SID_SIMPLE_EXP			32
#define ALG_SID_SIMPLE_EXP_M			87
#define ALG_SID_SIMPLE_EXP_K			88
#define ALG_SID_PRO12_EXP			33
#define ALG_SID_KEXP_2015_M			36
#define ALG_SID_KEXP_2015_K			37
#define ALG_SID_MGM_EXPORT_M			41
#define ALG_SID_MGM_EXPORT_K			42
/* GR3412 sub_ids*/
#define ALG_SID_GR3412_2015_M			48
#define ALG_SID_GR3412_2015_K			49
/* Hash sub ids */
#define ALG_SID_G28147_MAC			31
#define ALG_SID_G28147_CHV			48
#define ALG_SID_TLS1_MASTER_HASH		32
#define ALG_SID_TLS1PRF_2012_256		49
#define ALG_SID_TLS1_MASTER_HASH_2012_256	54
#define ALG_SID_TLS1_MD5_XOR_SHA1		15

/*MDC2 Hash id*/
#define ALG_SID_MDC2			0x11e

/*SHA Hash ids*/
#define	ALG_SID_SHA_224                 0x11d
#define ALG_SID_SHA_256                 12
#define ALG_SID_SHA_384                 13
#define ALG_SID_SHA_512                 14

/* SHA3 Hash ids */
#define ALG_SID_SHA3_224			77
#define ALG_SID_SHA3_256			78
#define ALG_SID_SHA3_384			79
#define ALG_SID_SHA3_512			80

/* GOST R 34.11-2012 hash sub ids */
#define ALG_SID_GR3411_2012_256			33
#define ALG_SID_GR3411_2012_512			34
#define ALG_SID_GR3411_2012_256_HMAC		52
#define ALG_SID_GR3411_2012_512_HMAC		53
#define ALG_SID_GR3411_2012_256_HMAC_FIXEDKEY	56
#define ALG_SID_GR3411_2012_512_HMAC_FIXEDKEY	57
#define ALG_SID_PBKDF2_2012_512			58
#define ALG_SID_PBKDF2_2012_256			59
#define ALG_SID_PBKDF2_94_256			64
#define ALG_SID_GR3411_PRFKEYMAT		74
#define ALG_SID_GR3411_2012_256_PRFKEYMAT	75
#define ALG_SID_GR3411_2012_512_PRFKEYMAT	76
#define ALG_SID_FOREIGN_PRFKEYMAT		83

/* GOST R 34.13-2015 hash sub ids */
#define ALG_SID_GR3413_2015_M_IMIT		60
#define ALG_SID_GR3413_2015_K_IMIT		61

#define ALG_SID_CMAC				62
#define ALG_SID_PBKDF2				63
#define ALG_SID_MGM_AUTH			65
#define ALG_SID_ANSI_X9_19_MAC			66
#define ALG_SID_KDF_TREE_HMAC_SHA_256		67

#define ALG_SID_HASH_VALUE_STORAGE		81

#define ALG_SID_ANSI_X963_KDF			82

#define ALG_SID_HASH_TO_CURVE			85
#define ALG_SID_HASH_TO_FIELD			86

#define ALG_SID_NO_HASH				84

/* VKO GOST R 34.10-2012 512-bit outputs sub-id*/
#define ALG_SID_SYMMETRIC_512			34

/* GOST_DH sub ids */
#define ALG_SID_DH_EX_SF			30
#define ALG_SID_DH_EX_EPHEM			31
#define ALG_SID_PRO_AGREEDKEY_DH		33
#define ALG_SID_GR3410				30
#define ALG_SID_GR3410EL			35
#define ALG_SID_GR3410_12_256			73
#define ALG_SID_GR3410_12_512			61
#define ALG_SID_DH_EL_SF			36
#define ALG_SID_DH_EL_EPHEM			37
#define ALG_SID_DH_GR3410_12_256_SF		70
#define ALG_SID_DH_GR3410_12_256_EPHEM		71
#define ALG_SID_DH_GR3410_12_512_SF		66
#define ALG_SID_DH_GR3410_12_512_EPHEM		67
#define ALG_SID_GR3410_94_ESDH			39
#define ALG_SID_GR3410_01_ESDH			40
#define ALG_SID_GR3410_12_256_ESDH		72
#define ALG_SID_GR3410_12_512_ESDH		63

#define ALG_SID_UECDIVERS			44
#define ALG_SID_UECSYMMETRIC			46
#define ALG_SID_UECSYMMETRIC_EPHEM		47

#define ALG_SID_GENERIC_SECRET			21
#define ALG_SID_GOST_GENERIC_SECRET		22
#define ALG_SID_HYBRID_SECRET			23

#define ALG_CLASS_UECSYMMETRIC                (6 << 13)

#define AT_UECSYMMETRICKEY		   0x80000004 //deprecated
#define AT_SYMMETRIC			   0x80000005


#define CALG_MDC2 \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_MDC2)

#ifndef CALG_SHA_224
#define CALG_SHA_224 \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_224)
#endif

#ifndef CALG_SHA_256
#define CALG_SHA_256 \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_256)
#endif

#ifndef CALG_SHA_384
#define CALG_SHA_384 \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_384)
#endif

#ifndef CALG_SHA_512
#define CALG_SHA_512 \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_512)
#endif

#define CALG_SHA3_224 \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA3_224)

#define CALG_SHA3_256 \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA3_256)

#define CALG_SHA3_384 \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA3_384)

#define CALG_SHA3_512 \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA3_512)

#define CALG_GR3411 \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_GR3411)

#define CALG_GR3411_2012_256 \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_GR3411_2012_256)

#define CALG_GR3411_2012_512 \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_GR3411_2012_512)

#define CALG_GR3411_HMAC \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_GR3411_HASH)
#define CALG_GR3411_HMAC34 \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_GR3411_HASH34)
#define CALG_UECMASTER_DIVERS \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_UECMASTER_DIVERS)
#define CALG_GR3411_HMAC_FIXEDKEY \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_GR3411_HMAC_FIXEDKEY)

#define CALG_GR3411_2012_256_HMAC \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_GR3411_2012_256_HMAC)
#define CALG_GR3411_2012_512_HMAC \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_GR3411_2012_512_HMAC)

#define CALG_GR3411_2012_256_HMAC_FIXEDKEY \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_GR3411_2012_256_HMAC_FIXEDKEY)
#define CALG_GR3411_2012_512_HMAC_FIXEDKEY \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_GR3411_2012_512_HMAC_FIXEDKEY)

#define CALG_GR3411_PRFKEYMAT \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_GR3411_PRFKEYMAT)
#define CALG_GR3411_2012_256_PRFKEYMAT \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_GR3411_2012_256_PRFKEYMAT)
#define CALG_GR3411_2012_512_PRFKEYMAT \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_GR3411_2012_512_PRFKEYMAT)
#define CALG_FOREIGN_PRFKEYMAT \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_FOREIGN_PRFKEYMAT)

#define CALG_G28147_MAC \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_G28147_MAC)

#define CALG_G28147_IMIT \
    CALG_G28147_MAC

#define CALG_GR3413_2015_M_IMIT \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_GR3413_2015_M_IMIT)

#define CALG_GR3413_2015_K_IMIT \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_GR3413_2015_K_IMIT)

#define CALG_CMAC \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_CMAC)

#define CALG_MGM_AUTH \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_MGM_AUTH)

#define CALG_ANSI_X9_19_MAC \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_ANSI_X9_19_MAC)

#define CALG_HASH_TO_CURVE \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_HASH_TO_CURVE)

#define CALG_HASH_TO_FIELD \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_HASH_TO_FIELD)

#define CALG_G28147_CHV \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_ANY | ALG_SID_G28147_MAC)

#define CALG_GR3410 \
    (ALG_CLASS_SIGNATURE | ALG_TYPE_GR3410 | ALG_SID_GR3410)

#define CALG_GR3410EL \
    (ALG_CLASS_SIGNATURE | ALG_TYPE_GR3410 | ALG_SID_GR3410EL)

#define CALG_GR3410_12_256 \
    (ALG_CLASS_SIGNATURE | ALG_TYPE_GR3410 | ALG_SID_GR3410_12_256)

#define CALG_GR3410_12_512 \
    (ALG_CLASS_SIGNATURE | ALG_TYPE_GR3410 | ALG_SID_GR3410_12_512)

#define CALG_G28147 \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_G28147)

#define CALG_SYMMETRIC_512 \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_SYMMETRIC_512)

#define CALG_GR3412_2015_M \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_GR3412_2015_M)

#define CALG_GR3412_2015_K \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_GR3412_2015_K)

#define CALG_DH_EX_SF \
    (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_DH_EX_SF)

#define CALG_DH_EX_EPHEM \
    (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_DH_EX_EPHEM)

#define CALG_DH_EX \
    CALG_DH_EX_SF

#define CALG_DH_EL_SF \
    (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_DH_EL_SF)

#define CALG_DH_EL_EPHEM \
    (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_DH_EL_EPHEM)

#define CALG_DH_GR3410_12_256_SF \
    (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_DH_GR3410_12_256_SF)

#define CALG_DH_GR3410_12_256_EPHEM \
    (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_DH_GR3410_12_256_EPHEM)

#define CALG_DH_GR3410_12_512_SF \
    (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_DH_GR3410_12_512_SF)

#define CALG_DH_GR3410_12_512_EPHEM \
    (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_DH_GR3410_12_512_EPHEM)

#define CALG_UECSYMMETRIC \
    (ALG_CLASS_UECSYMMETRIC | ALG_TYPE_BLOCK | ALG_SID_UECSYMMETRIC)
#define CALG_UECSYMMETRIC_EPHEM \
    (ALG_CLASS_UECSYMMETRIC | ALG_TYPE_BLOCK | ALG_SID_UECSYMMETRIC_EPHEM)


#define CALG_GR3410_94_ESDH \
    (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_GR3410_94_ESDH)

#define CALG_GR3410_01_ESDH \
    (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_GR3410_01_ESDH)

#define CALG_GR3410_12_256_ESDH \
    (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_GR3410_12_256_ESDH)

#define CALG_GR3410_12_512_ESDH \
    (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_GR3410_12_512_ESDH)

#define CALG_PRO_AGREEDKEY_DH \
    (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_BLOCK | ALG_SID_PRO_AGREEDKEY_DH)

#define CALG_PRO12_EXPORT \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_PRO12_EXP)

#define CALG_PRO_EXPORT \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_PRO_EXP)

#define CALG_SIMPLE_EXPORT \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_SIMPLE_EXP)

#define CALG_SIMPLE_EXPORT_K \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_SIMPLE_EXP_K)

#define CALG_SIMPLE_EXPORT_M \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_SIMPLE_EXP_M)

#define CALG_KEXP_2015_M \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_KEXP_2015_M)

#define CALG_KEXP_2015_K \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_KEXP_2015_K)

#define CALG_MGM_EXPORT_M \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_MGM_EXPORT_M)

#define CALG_MGM_EXPORT_K \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_MGM_EXPORT_K)

#define CALG_TLS1PRF_2012_256 \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_TLS1PRF_2012_256)

#define CALG_TLS1_MASTER_HASH \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_TLS1_MASTER_HASH)

#define CALG_TLS1_MASTER_HASH_2012_256 \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_TLS1_MASTER_HASH_2012_256)

#define CALG_TLS1_MD5_XOR_SHA1 \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_TLS1_MD5_XOR_SHA1)

#define CALG_TLS1_MAC_KEY \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_SECURECHANNEL | ALG_SID_SCHANNEL_MAC_KEY)

#define CALG_TLS1_ENC_KEY \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_SECURECHANNEL | ALG_SID_SCHANNEL_ENC_KEY)

#define CALG_PBKDF2_2012_512 \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_PBKDF2_2012_512)

#define CALG_PBKDF2_2012_256 \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_PBKDF2_2012_256)

#define CALG_PBKDF2_94_256 \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_PBKDF2_94_256)

#define CALG_PBKDF2 \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_PBKDF2)

#define CALG_HASH_VALUE_STORAGE \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_HASH_VALUE_STORAGE)

#define CALG_NO_HASH \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_NO_HASH)

#define CALG_SHAREDKEY_HASH \
    (ALG_CLASS_HASH | ALG_TYPE_SHAREDKEY | ALG_SID_SHAREDKEY_HASH)
#define CALG_FITTINGKEY_HASH \
    (ALG_CLASS_HASH | ALG_TYPE_SHAREDKEY | ALG_SID_FITTINGKEY_HASH)

#define CALG_GENERIC_SECRET \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_GENERIC_SECRET)

#define CALG_GOST_GENERIC_SECRET \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_GOST_GENERIC_SECRET)

#define CALG_HYBRID_SECRET \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_HYBRID_SECRET)

#define CALG_PRO_DIVERS \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_PRODIVERS)
#define CALG_RIC_DIVERS \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_RIC1DIVERS)
#define CALG_OSCAR_DIVERS CALG_RIC_DIVERS
#define CALG_PRO12_DIVERS \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_PRO12DIVERS)

#define CALG_KDF_TREE_GOSTR3411_2012_256 \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_KDF_TREE_GOSTR3411_2012_256)
#define CALG_KDF_TREE_HMAC_SHA_256 \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_KDF_TREE_HMAC_SHA_256)

#define CALG_ANSI_X963_KDF \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_ANSI_X963_KDF)

#ifndef CALG_ECDSA
    #ifndef ALG_SID_ECDSA
    #define ALG_SID_ECDSA                   3
    #endif
    #define CALG_ECDSA              (ALG_CLASS_SIGNATURE | ALG_TYPE_DSS | ALG_SID_ECDSA)
#endif

// Some DSS sub-ids
#define ALG_SID_ED25519                   32
#define ALG_SID_X25519_EPHEM              33

#define CALG_ED25519		    (ALG_CLASS_SIGNATURE | ALG_TYPE_DSS | ALG_SID_ED25519)
#define CALG_X25519		    (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_ED25519)
#define CALG_X25519_EPHEM	    (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_X25519_EPHEM)

#ifndef CALG_ECDH
    #ifndef ALG_SID_ECDH
    #define ALG_SID_ECDH                    5
    #endif
    #define CALG_ECDH               (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_ECDH)
#endif

#ifndef CALG_ECDH_EPHEM
    #ifndef ALG_TYPE_ECDH
    #define ALG_TYPE_ECDH                   (7 << 9)
    #endif
    #ifndef ALG_SID_ECDH_EPHEM
    #define ALG_SID_ECDH_EPHEM		    6
    #endif
    #define CALG_ECDH_EPHEM	    (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_ECDH | ALG_SID_ECDH_EPHEM)
#endif

#define IS_GOST_PROV(providerType) \
    (((providerType) == PROV_GOST_2001_DH) || \
     ((providerType) == PROV_GOST_2012_256) || \
     ((providerType) == PROV_GOST_2012_512))

#define IS_GOST_HASH(hashAlgId) \
    (((hashAlgId) == CALG_GR3411) || \
     ((hashAlgId) == CALG_GR3411_2012_256) || \
     ((hashAlgId) == CALG_GR3411_2012_512))

#ifndef szOID_ECC_PUBLIC_KEY
// iso(1) member-body(2) us(840) 10045 keyType(2) unrestricted(1)
#define szOID_ECC_PUBLIC_KEY	    "1.2.840.10045.2.1"
#endif

#ifndef szOID_ECC_CURVE_P256
// iso(1) member-body(2) us(840) 10045 curves(3) prime(1) 7
#define szOID_ECC_CURVE_P256	    "1.2.840.10045.3.1.7"
#endif

#ifndef szOID_ECC_CURVE_P384
// iso(1) identified-organization(3) certicom(132) curve(0) 34
#define szOID_ECC_CURVE_P384	    "1.3.132.0.34"
#endif

#ifndef szOID_ECC_CURVE_P521
// iso(1) identified-organization(3) certicom(132) curve(0) 35
#define szOID_ECC_CURVE_P521    "1.3.132.0.35"
#endif

#define szOID_EC_DH		    "1.3.132.1.12"
#define szOID_ECC_CURVE_P192	    "1.2.840.10045.3.1.1"
#define szOID_ECC_CURVE_P224	    "1.3.132.0.33"

#define szOID_ED25519		    "1.3.101.112"

#ifndef szOID_ECDSA_SHA224
// iso(1) member-body(2) us(840) 10045 signatures(4) specified(3) 1
#define szOID_ECDSA_SHA224	    "1.2.840.10045.4.3.1"
#endif

#ifndef szOID_ECDSA_SHA256
// iso(1) member-body(2) us(840) 10045 signatures(4) specified(3) 2
#define szOID_ECDSA_SHA256	    "1.2.840.10045.4.3.2"
#endif

#ifndef szOID_ECDSA_SHA384
// iso(1) member-body(2) us(840) 10045 signatures(4) specified(3) 3
#define szOID_ECDSA_SHA384	    "1.2.840.10045.4.3.3"
#endif

#ifndef szOID_ECDSA_SHA512
// iso(1) member-body(2) us(840) 10045 signatures(4) specified(3) 4
#define szOID_ECDSA_SHA512	    "1.2.840.10045.4.3.4"
#endif

#ifndef szOID_NIST_sha224
#define szOID_NIST_sha224	    "2.16.840.1.101.3.4.2.4"
#endif

#ifndef szOID_RSA_SHA224RSA
#define szOID_RSA_SHA224RSA	    "1.2.840.113549.1.1.14"
#endif

#ifndef PKCS12_PBKDF2_ID_HMAC_SHA256
#define PKCS12_PBKDF2_ID_HMAC_SHA256   "1.2.840.113549.2.9"
#endif

// NIST AES Algorithms
// joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithms(4)  aesAlgs(1)
#ifndef szOID_NIST_AES128_ECB
#define szOID_NIST_AES128_ECB		    "2.16.840.1.101.3.4.1.1"
#endif
#ifndef szOID_NIST_AES128_CBC
#define szOID_NIST_AES128_CBC		    "2.16.840.1.101.3.4.1.2"
#endif
#ifndef szOID_NIST_AES128_OFB
#define szOID_NIST_AES128_OFB		    "2.16.840.1.101.3.4.1.3"
#endif
#ifndef szOID_NIST_AES128_CFB
#define szOID_NIST_AES128_CFB		    "2.16.840.1.101.3.4.1.4"
#endif
#ifndef szOID_NIST_AES192_ECB
#define szOID_NIST_AES192_ECB		    "2.16.840.1.101.3.4.1.21"
#endif
#ifndef szOID_NIST_AES192_CBC
#define szOID_NIST_AES192_CBC		    "2.16.840.1.101.3.4.1.22"
#endif
#ifndef szOID_NIST_AES192_OFB
#define szOID_NIST_AES192_OFB		    "2.16.840.1.101.3.4.1.23"
#endif
#ifndef szOID_NIST_AES192_CFB
#define szOID_NIST_AES192_CFB		    "2.16.840.1.101.3.4.1.24"
#endif
#ifndef szOID_NIST_AES256_ECB
#define szOID_NIST_AES256_ECB		    "2.16.840.1.101.3.4.1.41"
#endif
#ifndef szOID_NIST_AES256_CBC
#define szOID_NIST_AES256_CBC		    "2.16.840.1.101.3.4.1.42"
#endif
#ifndef szOID_NIST_AES256_OFB
#define szOID_NIST_AES256_OFB		    "2.16.840.1.101.3.4.1.43"
#endif
#ifndef szOID_NIST_AES256_CFB
#define szOID_NIST_AES256_CFB		    "2.16.840.1.101.3.4.1.44"
#endif

// For old SDK
#ifndef CALG_OID_INFO_CNG_ONLY
// Algorithm is only implemented in CNG.
#   define CALG_OID_INFO_CNG_ONLY                   0xFFFFFFFF
#endif /*CALG_OID_INFO_CNG_ONLY*/

// For old SDK
#ifndef CALG_OID_INFO_PARAMETERS
// Algorithm is defined in the encoded parameters. Only supported
// using CNG.
#   define CALG_OID_INFO_PARAMETERS                 0xFFFFFFFE
// Macro to check for a special ALG_ID used in CRYPT_OID_INFO
#   define IS_SPECIAL_OID_INFO_ALGID(Algid)        (Algid >= CALG_OID_INFO_PARAMETERS)
#endif /*CALG_OID_INFO_PARAMETERS*/

#define SSL3_CK_GVO				0x0031
#define SSL3_CK_GVO_KB2				0x0032
#define	TLS_CIPHER_2001				0x0081
#define TLS_CIPHER_SCSV				0x00FF
#define TLS_CIPHER_2012				0xFF85
#define TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC 0xC100
#define TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC 0xC101
#define TLS_GOSTR341112_256_WITH_28147_CNT_IMIT 0xC102

#define TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L   0xC103
#define TLS_GOSTR341112_256_WITH_MAGMA_MGM_L	    0xC104
#define TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S   0xC105
#define TLS_GOSTR341112_256_WITH_MAGMA_MGM_S	    0xC106

#if !defined(TLS_RSA_WITH_AES_128_CBC_SHA) && !defined(IOS)
#define TLS_RSA_WITH_3DES_EDE_CBC_SHA   0x000a
#define TLS_RSA_WITH_AES_128_CBC_SHA    0x002f
#define TLS_RSA_WITH_AES_256_CBC_SHA    0x0035
#define TLS_RSA_WITH_AES_128_CBC_SHA256 0x003c
#define TLS_RSA_WITH_AES_256_CBC_SHA256 0x003d
#define TLS_RSA_WITH_AES_128_GCM_SHA256 0x009c
#define TLS_RSA_WITH_AES_256_GCM_SHA384 0x009d
#define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA	0xC009
#define TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA	0xC00A
#define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA	0xC013
#define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA	0xC014
#define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256	0xC023
#define TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384	0xC024
#define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256	0xC027
#define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384	0xC028
#define TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 0xC02B
#define TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 0xC02C
#define TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256	0xC02F
#define TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384	0xC030
#endif

#if !defined(TLS_AES_128_GCM_SHA256) && !defined(IOS)
#define TLS_AES_128_GCM_SHA256			0x1301
#endif

#if !defined(TLS_AES_256_GCM_SHA384) && !defined(IOS)
#define TLS_AES_256_GCM_SHA384			0x1302
#endif

#define TLS_LEGACY_SUITE_CNAME                                      "TLS_GOST_R_3410_WITH_28147_LEGACY"
#define TLS_CIPHER_94_SUITE_CNAME                                   "TLS_GOST_R_3410_94_WITH_28147_CNT_IMIT"
#define TLS_CIPHER_2001_SUITE_CNAME                                 "TLS_GOSTR341001_WITH_28147_CNT_IMIT"
#define TLS_CIPHER_2012_SUITE_CNAME                                 "TLS_GOSTR341112_256_WITH_28147_CNT_IMIT"
#define TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC_SUITE_CNAME    "TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC"
#define TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC_SUITE_CNAME         "TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC"
#define TLS_CIPHER_2012_SUITE_NAME_IANA_CNAME			    "TLS_GOSTR341112_256_WITH_28147_CNT_IMIT_IANA"
#define TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L_CNAME		    "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L"
#define TLS_GOSTR341112_256_WITH_MAGMA_MGM_L_CNAME		    "TLS_GOSTR341112_256_WITH_MAGMA_MGM_L"
#define TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S_CNAME		    "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S"
#define TLS_GOSTR341112_256_WITH_MAGMA_MGM_S_CNAME		    "TLS_GOSTR341112_256_WITH_MAGMA_MGM_S"

#define TLS_RSA_WITH_3DES_EDE_CBC_SHA_SUITE_CNAME                   "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
#define TLS_RSA_WITH_AES_128_CBC_SHA_SUITE_CNAME                    "TLS_RSA_WITH_AES_128_CBC_SHA"
#define TLS_RSA_WITH_AES_256_CBC_SHA_SUITE_CNAME                    "TLS_RSA_WITH_AES_256_CBC_SHA"
#define TLS_RSA_WITH_AES_128_CBC_SHA256_SUITE_CNAME                 "TLS_RSA_WITH_AES_128_CBC_SHA256"
#define TLS_RSA_WITH_AES_256_CBC_SHA256_SUITE_CNAME                 "TLS_RSA_WITH_AES_256_CBC_SHA256"
#define TLS_RSA_WITH_AES_128_GCM_SHA256_SUITE_CNAME                 "TLS_RSA_WITH_AES_128_GCM_SHA256"
#define TLS_RSA_WITH_AES_256_GCM_SHA384_SUITE_CNAME                 "TLS_RSA_WITH_AES_256_GCM_SHA384"
#define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_SUITE_CNAME	    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
#define TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_SUITE_CNAME	    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
#define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_SUITE_CNAME		    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
#define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_SUITE_CNAME		    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
#define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_SUITE_CNAME	    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
#define TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_SUITE_CNAME	    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"
#define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_SUITE_CNAME	    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
#define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_SUITE_CNAME	    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
#define TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_SUITE_CNAME	    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
#define TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_SUITE_CNAME	    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
#define TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256_SUITE_CNAME	    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
#define TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384_SUITE_CNAME	    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
#define TLS_AES_128_GCM_SHA256_SUITE_CNAME			    "TLS_AES_128_GCM_SHA256"
#define TLS_AES_256_GCM_SHA384_SUITE_CNAME			    "TLS_AES_256_GCM_SHA384"

#define TLS_LEGACY_SUITE_NAME                                       L"" TLS_LEGACY_SUITE_CNAME
#define TLS_CIPHER_94_SUITE_NAME                                    L"" TLS_CIPHER_94_SUITE_CNAME
#define TLS_CIPHER_2001_SUITE_NAME                                  L"" TLS_CIPHER_2001_SUITE_CNAME
#define TLS_CIPHER_2012_SUITE_NAME                                  L"" TLS_CIPHER_2012_SUITE_CNAME
#define TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC_SUITE_NAME     L"" TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC_SUITE_CNAME
#define TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC_SUITE_NAME          L"" TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC_SUITE_CNAME
#define TLS_CIPHER_2012_SUITE_NAME_IANA_NAME			    L"" TLS_CIPHER_2012_SUITE_NAME_IANA_CNAME
#define TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L_NAME		    L"" TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L_CNAME
#define TLS_GOSTR341112_256_WITH_MAGMA_MGM_L_NAME		    L"" TLS_GOSTR341112_256_WITH_MAGMA_MGM_L_CNAME
#define TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S_NAME		    L"" TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S_CNAME
#define TLS_GOSTR341112_256_WITH_MAGMA_MGM_S_NAME		    L"" TLS_GOSTR341112_256_WITH_MAGMA_MGM_S_CNAME

#define TLS_RSA_WITH_3DES_EDE_CBC_SHA_SUITE_NAME                    L"" TLS_RSA_WITH_3DES_EDE_CBC_SHA_SUITE_CNAME
#define TLS_RSA_WITH_AES_128_CBC_SHA_SUITE_NAME                     L"" TLS_RSA_WITH_AES_128_CBC_SHA_SUITE_CNAME
#define TLS_RSA_WITH_AES_256_CBC_SHA_SUITE_NAME                     L"" TLS_RSA_WITH_AES_256_CBC_SHA_SUITE_CNAME
#define TLS_RSA_WITH_AES_128_CBC_SHA256_SUITE_NAME                  L"" TLS_RSA_WITH_AES_128_CBC_SHA256_SUITE_CNAME
#define TLS_RSA_WITH_AES_256_CBC_SHA256_SUITE_NAME                  L"" TLS_RSA_WITH_AES_256_CBC_SHA256_SUITE_CNAME
#define TLS_RSA_WITH_AES_128_GCM_SHA256_SUITE_NAME                  L"" TLS_RSA_WITH_AES_128_GCM_SHA256_SUITE_CNAME
#define TLS_RSA_WITH_AES_256_GCM_SHA384_SUITE_NAME                  L"" TLS_RSA_WITH_AES_256_GCM_SHA384_SUITE_CNAME
#define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_SUITE_NAME		    L"" TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_SUITE_CNAME
#define TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_SUITE_NAME		    L"" TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_SUITE_CNAME
#define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_SUITE_NAME		    L"" TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_SUITE_CNAME
#define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_SUITE_NAME		    L"" TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_SUITE_CNAME
#define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_SUITE_NAME	    L"" TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_SUITE_CNAME
#define TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_SUITE_NAME	    L"" TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_SUITE_CNAME
#define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_SUITE_NAME	    L"" TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_SUITE_CNAME
#define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_SUITE_NAME	    L"" TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_SUITE_CNAME
#define TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_SUITE_NAME	    L"" TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_SUITE_CNAME
#define TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_SUITE_NAME	    L"" TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_SUITE_CNAME
#define TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256_SUITE_NAME	    L"" TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256_SUITE_CNAME
#define TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384_SUITE_NAME	    L"" TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384_SUITE_CNAME
#define TLS_AES_128_GCM_SHA256_SUITE_NAME			    L"" TLS_AES_128_GCM_SHA256_SUITE_CNAME
#define TLS_AES_256_GCM_SHA384_SUITE_NAME			    L"" TLS_AES_256_GCM_SHA384_SUITE_CNAME

#define ALG_TYPE_CIPHER_SUITE                   (15 << 9)

#define CALG_TLS_GOSTR341001_WITH_28147_CNT_IMIT \
    (ALG_TYPE_CIPHER_SUITE | TLS_CIPHER_2001)
#define CALG_TLS_GOSTR341112_256_WITH_28147_CNT_IMIT \
    (ALG_TYPE_CIPHER_SUITE | TLS_CIPHER_2012)

/* KP_PADDING for RSA*/
#define CRYPT_RSA_PKCS		0x00000050 // по умолчанию
#define CRYPT_RSA_X_509		0x00000051
#define CRYPT_RSA_RMASK		0x00000052

/* Максимальная длина ключа GENERIC_SECRET */
#define MAX_GENERIC_SECRET_KEY_BITLEN   4096
#define MAX_GENERIC_SECRET_KEYLEN	512

#define HYBRID_SECRET_KEY_BITLEN	512
#define HYBRID_SECRET_KEYLEN		64

#define MAX_GOST_GENERIC_SECRET_KEY_BITLEN	4096
#define MAX_GOST_GENERIC_SECRET_KEYLEN		512
#define MIN_GOST_GENERIC_SECRET_KEY_BITLEN	64
#define MIN_GOST_GENERIC_SECRET_KEYLEN		8

#define CRYPT_ALG_PARAM_OID_GROUP_ID            20


#define CRYPT_PROMIX_MODE	0x00000001
#define CRYPT_ACPKM_MODE        0x00000001
#define CRYPT_SIMPLEMIX_MODE	0x00000000
#define CRYPT_MIXDUPLICATE	0x00000002

/*Тип ключевого блоба для диверсификации ключей с помощью
    функции CPImportKey в режиме ключа импорта CALG_PRO_EXPORT*/
#define DIVERSKEYBLOB	0x70

/*Тип ключевого блоба для передачи параметров в протоколе подписи FKC*/
#define HASHPUBLICKEYEXBLOB 0x71

/*Тип ключевого блоба для диверсификации дерева ключей*/
#define KDF_TREE_DIVERSBLOB	0x72

/*Тип ключевого блоба PKCS#1 */
#define PKCS1KEYBLOB			    0x18

/*Тип ключевого блоба PKCS#8 */
#define PKCS8KEYBLOB			    0x19

#define RSA_CKM_EXTRACT_KEY_FROM_KEY        0xE
#define RSA_CKM_DES_ENCRYPT_DATA            0xF
#define RSA_CKM_CONCATENATE_BASE_AND_KEY    0x2
#define RSA_CKM_CONCATENATE_BASE_AND_DATA   0x3
#define RSA_CKM_CONCATENATE_DATA_AND_BASE   0x4
#define RSA_CKM_XOR_BASE_AND_DATA           0x5
#define RSA_CKM_SHA1_KEY_DERIVATION         0x11
#define RSA_CKM_AES_ENCRYPT_DATA            0x12

/* Дополнительные параметры криптопровайдера */
#if !(defined(CPCSP_C_SOURCE ) && CPCSP_C_SOURCE - 0 < 36) 
#define PP_LAST_ERROR 90 //deprecated
#endif
#define PP_ENUMOIDS_EX 91
#define PP_HASHOID 92
#define PP_CIPHEROID 93
#define PP_SIGNATUREOID 94
#define PP_DHOID 95
#define PP_RESERVED1 96
#define PP_BIO_STATISTICA_LEN 97
//#pragma deprecated("PP_REBOOT")
#define PP_REBOOT 98
/*Следующий параметр используется для перехода на платформы, отличные от WIN32*/
/*#define PP_ANSILASTERROR 99*/
#define PP_RANDOM 100
/*#define PP_DRVCONTAINER	101*/
#define PP_MUTEX_ARG	102
#define PP_ENUM_HASHOID 103
#define PP_ENUM_CIPHEROID 104
#define PP_ENUM_SIGNATUREOID 105
#define PP_ENUM_DHOID	106
#define PP_SET_PIN 107
#define PP_CHANGE_PIN 108
#define PP_HCRYPTPROV 109
#define PP_SELECT_CONTAINER 110
#define PP_FQCN 111
#define PP_CHECKPUBLIC 112
#define PP_ADMIN_CHECKPUBLIC 113
#define PP_ENUMREADERS 114
#define PP_CACHE_SIZE 115
#define PP_NK_SYNC 117
#define PP_INFO 118
#define PP_PIN_INFO 120
#define PP_PASSWD_TERM 123
#define PP_SAME_MEDIA 124
#define PP_DELETE_KEYSET 125
#define PP_DELETE_SAVED_PASSWD 126
#define PP_VERSION_TIMESTAMP 127
#define PP_SECURITY_LEVEL 129
#define PP_FAST_CODE_FUNCS 131
#define PP_CONTAINER_EXTENSION 132
#define PP_ENUM_CONTAINER_EXTENSION 133
#define PP_CONTAINER_EXTENSION_DEL 134
#define PP_CONTAINER_DEFAULT 135
#define PP_LCD_QUERY 136
#define PP_ENUM_LOG 137
#define PP_VERSION_EX 138
#define PP_FAST_CODE_FLAGS 139
#define PP_ENCRYPTION_CARRIER 140
#define PP_FKC				141
#define PP_FRIENDLY_NAME		142
#define PP_FKC_DH_CHECK			143
#define PP_DELETE_SHORTCUT 144
#define PP_SELFTEST	    145
#define PP_CONTAINER_STATUS  146
#define PP_PUBLIC_EXPONENT 147
#define PP_UEC 147
#define PP_UEC_PHRASE 148
#define PP_UEC_PIN1 149
#define PP_UEC_AUTH 150
#define PP_UEC_DATA_TAG 151
#define PP_UEC_DATA_BIN 152
#define PP_UEC_PUK 153
#define PP_UEC_NEED_PIN 154
#define PP_KEY_PERIOD 155
#define PP_UEC_CONTAINER_NAME 156
#define PP_UEC_CHANGE_PIN1 157
#define PP_LICENSE 158
#define PP_RESERVED2	     159
#define PP_RESERVED3         160	
#define PP_THREAD_ID 161
#define PP_CREATE_THREAD_CSP 162
#define PP_HANDLE_COUNT 163
#define PP_CONTAINER_VERSION 164
#define PP_PASSWORD_CACHE 165
#define PP_RNG_INITIALIZED 166
#define PP_CPU_USAGE 167
#define PP_MEMORY_USAGE 168
#define PP_CONTROL_KEY_TIME_VALIDITY 169
#define PP_CSP_MODE 170
#define PP_REFCOUNT 171
#define PP_RESERVED4         172
#define PP_RESERVED5         173

#define PP_SIGNATURE_KEY_FP 211
#define PP_EXCHANGE_KEY_FP 212
#define PP_SUPPORTED_FLAGS 213

/* Флаги, используемые в GetProvParam для получения текущего и максимального значий хэндлов.*/
#define CRYPT_CUR_HANDLES 0
#define CRYPT_MAX_HANDLES 1

/*Флаги, испльзуемые в GetProvParam(PP_CPU_USAGE и PP_MEMORY_USAGE) */
#define CPU_USAGE 0
#define CPU_USAGE_BY_PROC 1
#define VIRTUAL_MEMORY_TOTAL 0
#define VIRTUAL_MEMORY_USED 1
#define VIRTUAL_MEMORY_USED_BY_CURRENT_PROC 2
#define PHYSICAL_MEMORY_TOTAL 3
#define PHYSICAL_MEMORY_USED 4
#define PHYSICAL_MEMORY_USED_BY_CURRENT_PROC 5

#define PP_CARRIER_TYPES 217

#define PP_AUTH_INFO 218
#define PP_SET_AUTH 219
#define PP_CHANGE_AUTH 220
#define PP_SAVE_PASSWORD_POLICY 221
#define PP_CONTAINER_PARAM 222
#define PP_CARRIER_FLAGS 223
#define PP_ENUMRANDOMS 224
#define PP_HARDWARE_STORE_FLAGS 225

#define PP_EXTERNAL_CONTAINER_LINK 227
#define PP_UNIQUE_FILTER 228
#define PP_CARRIER_FREE_SPACE 229
#define PP_MEDIA_TYPE 231

/* Флаг, используемый при перечислении для получения свойств контейнера через
    поле property_flags. Возможные значения CRYPT_PROPERTY* приведены ниже. */
#define CRYPT_PROPERTIES 0x400

/* Флаг, позволяющий при перечислении выбирать только экспортируемые контейнеры.*/
#define CRYPT_FILTER_EXPORTABLE 0x200

/* Флаг, позволяющий при перечислении выбирать только контейнеры с ключами, 
    совпадающими с типом криптопровайдера.*/
#define CRYPT_FILTER_PROVIDER_TYPE 0x100

/* Флаг, используемый при перечислении считывателей, для получения только подключенных считывателей
*/
#define CRYPT_AVAILABLE 0x40

/* Флаг, используемый при перечислении считывателей, для получения имени носителя
*/
#define CRYPT_MEDIA 0x20

/* Флаг, используемый при перечислении контейнеров, для получения:
    Fully Qualified Container Name */
#define CRYPT_FQCN 0x10

/* Флаг, используемый при перечислении контейнеров, для приоритета
    получения уникальных имён контейнеров перед обычными именами.
    В случае достаточно выделенной памяти под уникальный номер,
    после уникального номера копируется обычное имя контейнера. */
#define CRYPT_UNIQUE 0x08

/* Флаг используемый при перечислении записей журнала,
   для завершения перечисления и вычисления подписи. */
#define CRYPT_FINISH 0x04

/* Флаг, при вызове PP_DELETE_ERROR и удалении контейнера разделённого
    на части выдаёт сообщение об ошибке. */
#define CRYPT_DELETEKEYSET_PART 0x1

/* Длина параметров, возвращаемых при использовании CRYPT_PROPERTIES (sizeof(BYTE) * 2). */
#define CRYPT_PROPERTIES_LENGTH 0x02

/* Флаг, возвращаемый для контейнера из перечисления контейнеров в случае вызова
     с флагом CRYPT_PROPERTIES. Означает, что контейнер является экспортируемым. */
#define CRYPT_PROPERTY_EXPORTABLE 0x01

/* Флаг, возвращаемый для контейнера из перечисления контейнеров в случае вызова
     с флагом CRYPT_PROPERTIES. Означает, что в этой версии поддерживается только
     передача флага CRYPT_PROPERTY_EXPORTABLE. */
#define CRYPT_PROPERTY_VERSION_1 0x01

/* Флаг, возвращаемый для контейнера из перечисления контейнеров в случае вызова
    с флагом CRYPT_PROPERTIES. Означает, что что информация о носителе для окна
    является низкоприоритетной. */
#define CRYPT_PROPERTY_MINOR_INFO 0x02

/* Флаг, возвращаемый для контейнера из перечисления контейнеров в случае вызова
    с флагом CRYPT_PROPERTIES. Означает, что в этой версии поддерживается передача
    флагов CRYPT_PROPERTY_EXPORTABLE и CRYPT_PROPERTY_MINOR_INFO. */
#define CRYPT_PROPERTY_VERSION_2 0x02

/* Ответ перечисления считывателей, означающий отсутствие носителя в считывателе. 
   Возвращается в виде ASCIIZ-строки. */
#define ERR_CRYPT_MEDIA_NO_MEDIA "NO_MEDIA"

/* Ответ перечисления считывателей, означающий, что вставлен не-ФКН. Для ФКН-провайдеров. 
   Возвращается в виде ASCIIZ-строки. */
#define ERR_CRYPT_MEDIA_NO_FKC "NO_FKC"

/* Ответ перечисления считывателей, означающий, что вставлен ФКН. Для не-ФКН-провайдеров.
   Возвращается в виде ASCIIZ-строки. */
#define ERR_CRYPT_MEDIA_FKC "IS_FKC"

/* Ответ перечисления считывателей, означающий отсутствие уникального номера носителя (неотчуждаемый носитель).
   Возвращается в виде ASCIIZ-строки. */
#define ERR_CRYPT_MEDIA_NO_UNIQUE "NO_UNIQUE"

/* Ответ перечисления считывателей, означающий, что вставлен испорченный носитель. 
   Не-ФКН-провайдер может возвращать эту ошибку для ФК-носителя.
   Возвращается в виде ASCIIZ-строки. */
#define ERR_CRYPT_MEDIA_INVALID "INVALID_MEDIA"

#define CARRIER_CLIENT_IDENTIFIER_SIZE 8

/*Максимально допустимая длина строки для PP_UNIQUE_FILTER*/
#define CARRIER_MAX_UNIQUE_FILTER_LEN 255

/*Максимально допусимая длина строки для PP_MEDIA_TYPE*/
#define CARRIER_MAX_MEDIA_TYPE_LEN 255

/* Дополнительные параметры объекта хэша */
#define HP_HASHSTARTVECT 0x0008
#define HP_HASHCOPYVAL	 0x0009
#define HP_OID 0x000a
#define HP_OPEN 0x000B
#define HP_OPAQUEBLOB 0x000C

#define HP_KEYSPEC_SIGN	    0x0010
#define HP_KEYMIXSTART	    0x0011
#define HP_SHAREDKEYMODE    0x0012
#define HP_SHAREDKEYALGID   0x0013
#define HP_DISPLAY_DTBS	    0x0014
#define HP_HMAC_FIXEDKEY    0x0015
#define	HP_IKE_SPI_COOKIE   0x0016
#define HP_PBKDF2_SALT	    0x0017
#define HP_PBKDF2_PASSWORD  0x0018
#define HP_PBKDF2_COUNT	    0x0019
#define HP_PRFKEYMAT_SEED   0x0020
#define HP_HASHVAL_BLOB	    0x0021
#define HP_PBKDF2_HASH_ALGID 0x0022
#define HP_PADDING	    0x0023
#define HP_HASHSTATEBLOB    0x0024
#define HP_RSA_PSS_SALTLEN  0x0025
#define HP_HASH_TO_GROUP_HASH_ALGID 0x0026
#define HP_HASH_TO_GROUP_DST 0x0027
#define HP_HMAC_VERIFICATION_VALUE 0x0028
#define HP_SIGN_VERIFICATION_VALUE 0x0029
#define HP_CERTIFICATE	    0x0030

/* Дополнительные параметры ключа */
#define KP_START_DATE	43
#define KP_END_DATE	44
#define KP_UEC_DERIVE_COUNTER 45
#define KP_HANDLE	46
#define KP_SV		KP_IV
#define KP_MIXMODE	101
#define KP_MIXSTART	0x800000e0
#define KP_OID		102
#define KP_HASHOID	103
#define KP_CIPHEROID	104
#define KP_SIGNATUREOID 105
#define KP_DHOID	106
#define KP_FP		107
#define KP_IV_BLOB	108
#define KP_NOTAFTER     109
#define KP_SESSION_HASH 110
#define KP_MIX_BLOCK_SIZE 111
#define KP_AUTH_TAG	112
#define KP_AUTH_DATA	113
#define KP_OAEP_HASH	114

#define KP_MULX		0x800000f1
#define KP_ADDX		0x800000f3
#define KP_INVERSE	0x800000ed
#define KP_ARANDOM	0x800000ee
#define KP_KC1EXPORT	0x800000f0
#define KP_CHECK_VALUE	0x800000fa

#define KP_STORE	0x800000ff

#define KP_KEY_LIFETIME	    0x800000ec
#define KP_KEY_EXHAUSTION   0x800000ef
#define KP_RESERVED1	    0x800000fb
#define KP_RESERVED2	    0x800000fc
#define KP_ACCLEN	    0x800000fd
#define KP_RESERVED3	    0x800000fe
#define KP_AUDIT_CONTROL    0x800000d1
#define KP_AUDIT_STATE      0x800000d2

#define CONTAINER_INVALID_HEADER (1<<0)
#define CONTAINER_INVALID_UNKNOWN (1<<30)

/* CRYPT_PRIVATE_KEYS_ALG_OID_GROUP_ID */
#define szOID_CP_GOST_PRIVATE_KEYS_V1 "1.2.643.2.2.37.1"
#define szOID_CP_GOST_PRIVATE_KEYS_V2 "1.2.643.2.2.37.2"
#define szOID_CP_GOST_PRIVATE_KEYS_V2_FULL "1.2.643.2.2.37.2.1"
#define szOID_CP_GOST_PRIVATE_KEYS_V2_PARTOF "1.2.643.2.2.37.2.2"

/* CRYPT_HASH_ALG_OID_GROUP_ID */
#define szOID_CP_GOST_R3411 "1.2.643.2.2.9"
#define szOID_CP_GOST_R3411_12_256 "1.2.643.7.1.1.2.2"
#define szOID_CP_GOST_R3411_12_512 "1.2.643.7.1.1.2.3"

/* CRYPT_ENCRYPT_ALG_OID_GROUP_ID */
#define szOID_CP_GOST_28147 "1.2.643.2.2.21"
#define szOID_CP_GOST_R3412_2015_M "1.2.643.7.1.1.5.1"
#define szOID_CP_GOST_R3412_2015_K "1.2.643.7.1.1.5.2"
#define szOID_CP_GOST_R3412_2015_M_CTR_ACPKM "1.2.643.7.1.1.5.1.1"
#define szOID_CP_GOST_R3412_2015_M_CTR_ACPKM_OMAC "1.2.643.7.1.1.5.1.2"
#define szOID_CP_GOST_R3412_2015_K_CTR_ACPKM "1.2.643.7.1.1.5.2.1"
#define szOID_CP_GOST_R3412_2015_K_CTR_ACPKM_OMAC "1.2.643.7.1.1.5.2.2"

#define szOID_CP_GOST_R3412_2015_M_KEXP15 "1.2.643.7.1.1.7.1.1"
#define szOID_CP_GOST_R3412_2015_K_KEXP15 "1.2.643.7.1.1.7.2.1"

/* CRYPT_PUBKEY_ALG_OID_GROUP_ID */
#define szOID_CP_GOST_R3410 "1.2.643.2.2.20"
#define szOID_CP_GOST_R3410EL "1.2.643.2.2.19"
#define szOID_CP_GOST_R3410_12_256 "1.2.643.7.1.1.1.1"
#define szOID_CP_GOST_R3410_12_512 "1.2.643.7.1.1.1.2"
#define szOID_CP_DH_EX "1.2.643.2.2.99"
#define szOID_CP_DH_EL "1.2.643.2.2.98"
#define szOID_CP_DH_12_256 "1.2.643.7.1.1.6.1"
#define szOID_CP_DH_12_512 "1.2.643.7.1.1.6.2"
#define szOID_CP_GOST_R3410_94_ESDH "1.2.643.2.2.97"
#define szOID_CP_GOST_R3410_01_ESDH "1.2.643.2.2.96"

/* CRYPT_SIGN_ALG_OID_GROUP_ID */
#define szOID_CP_GOST_R3411_R3410 "1.2.643.2.2.4"
#define szOID_CP_GOST_R3411_R3410EL "1.2.643.2.2.3"
#define szOID_CP_GOST_R3411_12_256_R3410 "1.2.643.7.1.1.3.2"
#define szOID_CP_GOST_R3411_12_512_R3410 "1.2.643.7.1.1.3.3"

/* CRYPT_ENHKEY_USAGE_OID_GROUP_ID */
#define szOID_KP_TLS_PROXY "1.2.643.2.2.34.1"
#define szOID_KP_RA_CLIENT_AUTH "1.2.643.2.2.34.2"
#define szOID_KP_WEB_CONTENT_SIGNING "1.2.643.2.2.34.3"
#define szOID_KP_RA_ADMINISTRATOR "1.2.643.2.2.34.4"
#define szOID_KP_RA_OPERATOR "1.2.643.2.2.34.5"

/* HMAC algorithms */
#define szOID_CP_GOST_R3411_94_HMAC "1.2.643.2.2.10"
#define szOID_CP_GOST_R3411_2012_256_HMAC "1.2.643.7.1.1.4.1"
#define szOID_CP_GOST_R3411_2012_512_HMAC "1.2.643.7.1.1.4.2"

/* Qualified Certificate */
#define szOID_OGRN "1.2.643.100.1"
#define szOID_OGRNIP "1.2.643.100.5"
#define szOID_SNILS "1.2.643.100.3"
#define szOID_INNLE "1.2.643.100.4"
#define szOID_INN "1.2.643.3.131.1.1"

/* Signature tool class */
#define szOID_SIGN_TOOL_KC1 "1.2.643.100.113.1"
#define szOID_SIGN_TOOL_KC2 "1.2.643.100.113.2"
#define szOID_SIGN_TOOL_KC3 "1.2.643.100.113.3"
#define szOID_SIGN_TOOL_KB1 "1.2.643.100.113.4"
#define szOID_SIGN_TOOL_KB2 "1.2.643.100.113.5"
#define szOID_SIGN_TOOL_KA1 "1.2.643.100.113.6"

/* CA tool class */
#define szOID_CA_TOOL_KC1 "1.2.643.100.114.1"
#define szOID_CA_TOOL_KC2 "1.2.643.100.114.2"
#define szOID_CA_TOOL_KC3 "1.2.643.100.114.3"
#define szOID_CA_TOOL_KB1 "1.2.643.100.114.4"
#define szOID_CA_TOOL_KB2 "1.2.643.100.114.5"
#define szOID_CA_TOOL_KA1 "1.2.643.100.114.6"

/* Our well-known policy ID */
#define szOID_CEP_BASE_PERSONAL	"1.2.643.2.2.38.1"
#define szOID_CEP_BASE_NETWORK	"1.2.643.2.2.38.2"

/* OIDs for HASH */
#define szOID_GostR3411_94_TestParamSet			"1.2.643.2.2.30.0"
#define szOID_GostR3411_94_CryptoProParamSet		"1.2.643.2.2.30.1"	/* ГОСТ Р 34.11-94, параметры по умолчанию */
#define szOID_GostR3411_94_CryptoPro_B_ParamSet		"1.2.643.2.2.30.2"
#define szOID_GostR3411_94_CryptoPro_C_ParamSet		"1.2.643.2.2.30.3"
#define szOID_GostR3411_94_CryptoPro_D_ParamSet		"1.2.643.2.2.30.4"

/* OIDs for Crypt */
#define szOID_Gost28147_89_TestParamSet			"1.2.643.2.2.31.0"
#define szOID_Gost28147_89_CryptoPro_A_ParamSet		"1.2.643.2.2.31.1"	/* ГОСТ 28147-89, параметры по умолчанию */
#define szOID_Gost28147_89_CryptoPro_B_ParamSet		"1.2.643.2.2.31.2"	/* ГОСТ 28147-89, параметры шифрования 1 */
#define szOID_Gost28147_89_CryptoPro_C_ParamSet		"1.2.643.2.2.31.3" 	/* ГОСТ 28147-89, параметры шифрования 2 */
#define szOID_Gost28147_89_CryptoPro_D_ParamSet		"1.2.643.2.2.31.4"	/* ГОСТ 28147-89, параметры шифрования 3 */
#define szOID_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet	"1.2.643.2.2.31.5"	/* ГОСТ 28147-89, параметры Оскар 1.1 */
#define szOID_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet	"1.2.643.2.2.31.6"	/* ГОСТ 28147-89, параметры Оскар 1.0 */
#define szOID_Gost28147_89_CryptoPro_RIC_1_ParamSet	"1.2.643.2.2.31.7"	/* ГОСТ 28147-89, параметры РИК 1 */

#define szOID_Gost28147_89_TC26_A_ParamSet		"1.2.643.2.2.31.12"	/* ГОСТ 28147-89, параметры шифрования TC26 2 */
#define szOID_Gost28147_89_TC26_B_ParamSet		"1.2.643.2.2.31.13"	/* ГОСТ 28147-89, параметры шифрования TC26 1 */
#define szOID_Gost28147_89_TC26_C_ParamSet		"1.2.643.2.2.31.14" 	/* ГОСТ 28147-89, параметры шифрования TC26 3 */
#define szOID_Gost28147_89_TC26_D_ParamSet		"1.2.643.2.2.31.15"	/* ГОСТ 28147-89, параметры шифрования TC26 4 */
#define szOID_Gost28147_89_TC26_E_ParamSet		"1.2.643.2.2.31.16" 	/* ГОСТ 28147-89, параметры шифрования TC26 5 */
#define szOID_Gost28147_89_TC26_F_ParamSet		"1.2.643.2.2.31.17"	/* ГОСТ 28147-89, параметры шифрования TC26 6 */

#define szOID_Gost28147_89_TC26_Z_ParamSet	"1.2.643.7.1.2.5.1.1"	/* ГОСТ 28147-89, параметры шифрования ТС26 Z */

/* OID for Signature 1024*/
#define szOID_GostR3410_94_CryptoPro_A_ParamSet		"1.2.643.2.2.32.2" 	/*VerbaO*/
#define szOID_GostR3410_94_CryptoPro_B_ParamSet		"1.2.643.2.2.32.3"
#define szOID_GostR3410_94_CryptoPro_C_ParamSet		"1.2.643.2.2.32.4"
#define szOID_GostR3410_94_CryptoPro_D_ParamSet		"1.2.643.2.2.32.5"

/* OID for Signature 512*/
#define szOID_GostR3410_94_TestParamSet			"1.2.643.2.2.32.0" 	/*Test*/

/* OID for DH 1024*/
#define szOID_GostR3410_94_CryptoPro_XchA_ParamSet	"1.2.643.2.2.33.1"
#define szOID_GostR3410_94_CryptoPro_XchB_ParamSet	"1.2.643.2.2.33.2"
#define szOID_GostR3410_94_CryptoPro_XchC_ParamSet	"1.2.643.2.2.33.3"

/* OID for EC signature */
#define szOID_GostR3410_2001_TestParamSet		"1.2.643.2.2.35.0"      /* ГОСТ Р 34.10 256 бит, тестовые параметры */
#define szOID_GostR3410_2001_CryptoPro_A_ParamSet	"1.2.643.2.2.35.1"	/* ГОСТ Р 34.10 256 бит, параметры по умолчанию */
#define szOID_GostR3410_2001_CryptoPro_B_ParamSet	"1.2.643.2.2.35.2"	/* ГОСТ Р 34.10 256 бит, параметры Оскар 2.x */
#define szOID_GostR3410_2001_CryptoPro_C_ParamSet	"1.2.643.2.2.35.3"	/* ГОСТ Р 34.10 256 бит, параметры подписи 1 */

#define szOID_tc26_gost_3410_12_256_paramSetA		"1.2.643.7.1.2.1.1.1"	/* ГОСТ Р 34.10-2012, 256 бит, параметры ТК-26, набор A */
#define szOID_tc26_gost_3410_12_256_paramSetB		"1.2.643.7.1.2.1.1.2"	/* ГОСТ Р 34.10-2012, 256 бит, параметры ТК-26, набор B */
#define szOID_tc26_gost_3410_12_256_paramSetC		"1.2.643.7.1.2.1.1.3"	/* ГОСТ Р 34.10-2012, 256 бит, параметры ТК-26, набор C */
#define szOID_tc26_gost_3410_12_256_paramSetD		"1.2.643.7.1.2.1.1.4"	/* ГОСТ Р 34.10-2012, 256 бит, параметры ТК-26, набор D */

#define szOID_tc26_gost_3410_12_512_paramSetTest	"1.2.643.7.1.2.1.2.0"	/* ГОСТ Р 34.10-2012, 512 бит, тестовые параметры */
#define szOID_tc26_gost_3410_12_512_paramSetA		"1.2.643.7.1.2.1.2.1"	/* ГОСТ Р 34.10-2012, 512 бит, параметры по умолчанию */
#define szOID_tc26_gost_3410_12_512_paramSetB		"1.2.643.7.1.2.1.2.2"	/* ГОСТ Р 34.10-2012, 512 бит, параметры ТК-26, набор B */
#define szOID_tc26_gost_3410_12_512_paramSetC		"1.2.643.7.1.2.1.2.3"	/* ГОСТ Р 34.10-2012, 512 бит, параметры ТК-26, набор С */


/* OID for EC DH */
#define szOID_GostR3410_2001_CryptoPro_XchA_ParamSet	"1.2.643.2.2.36.0"	/* ГОСТ Р 34.10 256 бит, параметры обмена по умолчанию */
#define szOID_GostR3410_2001_CryptoPro_XchB_ParamSet 	"1.2.643.2.2.36.1"	/* ГОСТ Р 34.10 256 бит, параметры обмена 1 */

/* OIDs for private key container extensions */
/* Расширения контейнера. Поддерживаются начиная с CSP 3.6 */
#define szOID_CryptoPro_private_keys_extension_intermediate_store "1.2.643.2.2.37.3.1"
#define szOID_CryptoPro_private_keys_extension_signature_trust_store "1.2.643.2.2.37.3.2"
#define szOID_CryptoPro_private_keys_extension_exchange_trust_store "1.2.643.2.2.37.3.3"
#define szOID_CryptoPro_private_keys_extension_container_friendly_name "1.2.643.2.2.37.3.4"
#define szOID_CryptoPro_private_keys_extension_container_key_usage_period "1.2.643.2.2.37.3.5"
#define szOID_CryptoPro_private_keys_extension_container_uec_symmetric_key_derive_counter "1.2.643.2.2.37.3.6"

#define szOID_CryptoPro_private_keys_extension_container_primary_key_properties "1.2.643.2.2.37.3.7"
#define szOID_CryptoPro_private_keys_extension_container_secondary_key_properties "1.2.643.2.2.37.3.8"

#define szOID_CryptoPro_private_keys_extension_container_signature_key_usage_period "1.2.643.2.2.37.3.9"
#define szOID_CryptoPro_private_keys_extension_container_exchange_key_usage_period "1.2.643.2.2.37.3.10"
#define szOID_CryptoPro_private_keys_extension_container_key_time_validity_control_mode "1.2.643.2.2.37.3.11"

#define szOID_CryptoPro_private_keys_extension_container_arandom_state "1.2.643.2.2.37.3.13"
#define szOID_CryptoPro_private_keys_extension_container_shared_container "1.2.643.2.2.37.3.14"

#define szOID_CryptoPro_private_keys_extension_license "1.2.643.2.2.37.3.15"

#define szOID_CryptoPro_private_keys_extension_container_string_config "1.2.643.2.2.37.3.17"

/* OIDs for certificate and CRL extensions */
/* Метод сопоставления CRL с сертификатом издателя. */
#define szOID_CryptoPro_extensions_certificate_and_crl_matching_technique "1.2.643.2.2.49.1"
/* Средство электронной подписи владельца */
#define szCPOID_SubjectSignTool "1.2.643.100.111"
/* Средства электронной подписи и УЦ издателя*/
#define szCPOID_IssuerSignTool "1.2.643.100.112"
/* Тип идентификации при выдаче сертификата */
#define szOID_IdentificationKind "1.2.643.100.114"

/* OID для атрибута id-cms-mac-attr в CMS 2015*/
#define szCPOID_CMS_GR3412_OMAC "1.2.643.7.1.0.6.1.1"

/* OIDs for signing certificate attributes */
/* Группа атрибутов для хранения идентификатора сертификата ключа подписи */
#define szCPOID_RSA_SMIMEaaSigningCertificate "1.2.840.113549.1.9.16.2.12"
#define szCPOID_RSA_SMIMEaaSigningCertificateV2 "1.2.840.113549.1.9.16.2.47"
#define szCPOID_RSA_SMIMEaaETSotherSigCert "1.2.840.113549.1.9.16.2.19"

/* OIDs ECDH single pass SHA key derivation */
#define szOID_DH_SINGLE_PASS_STDDH_SHA224_KDF	"1.3.132.1.11.0"
#define szOID_DH_SINGLE_PASS_STDDH_SHA512_KDF	"1.3.132.1.11.3"

/* GUIDs for extending CryptEncodeObject/CryptDecodeObject functionality */
/* Набор уникальных идентификаторов, используемых для расширения функциональности
   функций CryptEncodeObject/CryptDecodeObject */
#define szCPGUID_RSA_SMIMEaaSigningCertificateEncode "{272ED084-4C55-42A9-AD88-A1502D9ED755}"
#define szCPGUID_RSA_SMIMEaaSigningCertificateV2Encode "{42AB327A-BE56-4899-9B81-1BF2F3C5E154}"
#define szCPGUID_RSA_SMIMEaaETSotherSigCertEncode "{410F6306-0ADE-4485-80CC-462DEB3AD109}"
#define szCPGUID_PRIVATEKEY_USAGE_PERIOD_Encode "{E36FC6F5-4880-4CB7-BA51-1FCD92CA1453}"

/*! \cond pkivalidator */
/* GUIDs for extending CertVerifyCertificateChainPolicy functionality */
/* Набор уникальных идентификаторов, используемых для расширения функциональности
   функции CertVerifyCertificateChainPolicy */
#define CPCERT_CHAIN_POLICY_PRIVATEKEY_USAGE_PERIOD "{C03D5610-26C8-4B6F-9549-245B5B3AB743}"
#define CPCERT_CHAIN_POLICY_SIGNATURE "{B52FF66F-13A5-402C-B958-A3A6B5300FB6}"
#define CPCERT_CHAIN_POLICY_TIMESTAMP_SIGNING "{AF74EE92-A059-492F-9B4B-EAD239B22A1B}"
#define CPCERT_CHAIN_POLICY_OCSP_SIGNING "{A4CC781E-04E9-425C-AAFD-1D74DA8DFAF6}"
/** \endcond */

/*! \cond csp */
/* Синонимы для совместимости с версией 3.0*/
#define OID_HashVar_Default	szOID_GostR3411_94_CryptoProParamSet
#define OID_HashTest		szOID_GostR3411_94_TestParamSet
#define OID_HashVerbaO		szOID_GostR3411_94_CryptoProParamSet
#define OID_HashVar_1		szOID_GostR3411_94_CryptoPro_B_ParamSet
#define OID_HashVar_2		szOID_GostR3411_94_CryptoPro_C_ParamSet
#define OID_HashVar_3		szOID_GostR3411_94_CryptoPro_D_ParamSet

#define OID_CipherVar_Default	szOID_Gost28147_89_CryptoPro_A_ParamSet
#define OID_CryptTest		szOID_Gost28147_89_TestParamSet
#define OID_CipherVerbaO	szOID_Gost28147_89_CryptoPro_A_ParamSet
#define OID_CipherVar_1		szOID_Gost28147_89_CryptoPro_B_ParamSet
#define OID_CipherVar_2		szOID_Gost28147_89_CryptoPro_C_ParamSet
#define OID_CipherVar_3		szOID_Gost28147_89_CryptoPro_D_ParamSet
#define OID_CipherOSCAR		szOID_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet
#define OID_CipherTestHash	szOID_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet
#define OID_CipherRIC1		szOID_Gost28147_89_CryptoPro_RIC_1_ParamSet

#define OID_CipherTC26_1	szOID_Gost28147_89_TC26_A_ParamSet	
#define OID_CipherTC26_2	szOID_Gost28147_89_TC26_B_ParamSet	
#define OID_CipherTC26_3	szOID_Gost28147_89_TC26_C_ParamSet	
#define OID_CipherTC26_4	szOID_Gost28147_89_TC26_D_ParamSet	
#define OID_CipherTC26_5	szOID_Gost28147_89_TC26_E_ParamSet	
#define OID_CipherTC26_6	szOID_Gost28147_89_TC26_F_ParamSet

#define OID_CipherRSTC26_1	szOID_Gost28147_89_TC26_Z_ParamSet

#define OID_SignDH128VerbaO	szOID_GostR3410_94_CryptoPro_A_ParamSet
#define OID_Sign128Var_1	szOID_GostR3410_94_CryptoPro_B_ParamSet
#define OID_Sign128Var_2	szOID_GostR3410_94_CryptoPro_C_ParamSet
#define OID_Sign128Var_3	szOID_GostR3410_94_CryptoPro_D_ParamSet
#define OID_DH128Var_1		szOID_GostR3410_94_CryptoPro_XchA_ParamSet
#define OID_DH128Var_2		szOID_GostR3410_94_CryptoPro_XchB_ParamSet
#define OID_DH128Var_3		szOID_GostR3410_94_CryptoPro_XchC_ParamSet

#define OID_Sg64_Test		szOID_GostR3410_94_TestParamSet

#define OID_ECCTest3410		szOID_GostR3410_2001_TestParamSet
#define OID_ECCSignDHPRO	szOID_GostR3410_2001_CryptoPro_A_ParamSet
#define OID_ECCSignDHOSCAR	szOID_GostR3410_2001_CryptoPro_B_ParamSet
#define OID_ECCSignDHVar_1	szOID_GostR3410_2001_CryptoPro_C_ParamSet

#define OID_ECC1024A		szOID_tc26_gost_3410_12_512_paramSetA
#define OID_ECC1024B		szOID_tc26_gost_3410_12_512_paramSetB


#define OID_ECCDHPRO		szOID_GostR3410_2001_CryptoPro_XchA_ParamSet
#define OID_ECCDHPVar_1		szOID_GostR3410_2001_CryptoPro_XchB_ParamSet

/* Синонимы для совместимости с версией 1.1*/
#define OID_SipherVerbaO	szOID_Gost28147_89_CryptoPro_A_ParamSet
#define OID_SipherVar_1		szOID_Gost28147_89_CryptoPro_B_ParamSet
#define OID_SipherVar_2		szOID_Gost28147_89_CryptoPro_C_ParamSet
#define OID_SipherVar_3		szOID_Gost28147_89_CryptoPro_D_ParamSet
#define OID_SipherVar_Default	szOID_Gost28147_89_CryptoPro_A_ParamSet

#define X509_GR3410_PARAMETERS ((LPCSTR) 5001)
#define OBJ_ASN1_CERT_28147_ENCRYPTION_PARAMETERS ((LPCSTR) 5007)

typedef struct _CRYPT_X509_GR3410_2012_PARAMETERS {
    LPSTR pPublicKeyParamSet;
    LPSTR pDigestParamSet;
    LPSTR pEncryptionParamSet;
} CRYPT_X509_GR3410_2012_PARAMETERS, *LPCRYPT_X509_GR3410_2012_PARAMETERS;

//short names
#define CP_GOST_28147_ALG			"GOST 28147-89"
#define CP_GOST_R3412_2015_M_ALG		"GR 34.12-15 M"
#define CP_GOST_R3412_2015_K_ALG		"GR 34.12-15 K"
#define CP_GOST_28147_MAC_ALG			"GOST 28147-89 MAC"
#define CP_GOST_R3413_2015_M_MAC_ALG		"GR 34.13-15 M MAC"
#define CP_GOST_R3413_2015_K_MAC_ALG		"GR 34.13-15 K MAC"
#define CP_GOST_HMAC_ALG			"HMAC GOST 28147-89"
#define CP_GOST_R3411_ALG			"GOST R 34.11-94"
#define CP_GOST_R3411_2012_256_ALG		"GR 34.11-2012 256"
#define CP_GOST_R3411_2012_512_ALG		"GR 34.11-2012 512"
#define CP_GOST_R3411_HMAC_ALG			"GR34.11-94 256 HMAC"
#define CP_GOST_R3411_2012_256_HMAC_ALG		"GR34.11-12 256 HMAC"
#define CP_GOST_R3411_2012_512_HMAC_ALG		"GR34.11-12 512 HMAC"
#define CP_GOST_R3410EL_ALG			"GOST R 34.10-2001"
#define CP_GOST_R3410_2012_256_ALG		"GR 34.10-2012 256"
#define CP_GOST_R3410_2012_512_ALG		"GR 34.10-2012 512"
#define CP_GOST_R3410EL_DH_ALG			"DH 34.10-2001"
#define CP_GOST_R3410_2012_256_DH_ALG		"DH 34.10-2012 256"
#define CP_GOST_R3410_2012_512_DH_ALG		"DH 34.10-2012 512"

#define CP_GOST_28147_ALGORITHM			"GOST 28147-89"
#define CP_GOST_R3412_2015_M_ALGORITHM		"GOST R 34.12-2015 64 Magma"
#define CP_GOST_R3412_2015_K_ALGORITHM		"GOST R 34.12-2015 128 Kuznyechik"
#define CP_GOST_28147_MAC_ALGORITHM		"GOST 28147-89 MAC"
#define CP_GOST_R3413_2015_M_MAC_ALGORITHM	"GOST R 34.13-2015 64 Magma MAC"
#define CP_GOST_R3413_2015_K_MAC_ALGORITHM	"GOST R 34.13-2015 128 Kuznyechik MAC"
#define CP_GOST_HMAC_ALGORITHM			"HMAC GOST 28147-89"
#define CP_GOST_R3411_ALGORITHM			"GOST R 34.11-1994 256"
#define CP_GOST_R3411_2012_256_ALGORITHM	"GOST R 34.11-2012 256"
#define CP_GOST_R3411_2012_512_ALGORITHM	"GOST R 34.11-2012 512"
#define CP_GOST_R3411_HMAC_ALGORITHM		"GOST R 34.11-1994 256 HMAC"
#define CP_GOST_R3411_2012_256_HMAC_ALGORITHM	"GOST R 34.11-2012 256 HMAC"
#define CP_GOST_R3411_2012_512_HMAC_ALGORITHM	"GOST R 34.11-2012 512 HMAC"
#define CP_GOST_R3410EL_ALGORITHM		"GOST R 34.10-2001 256"
#define CP_GOST_R3410_2012_256_ALGORITHM	"GOST R 34.10-2012 256"
#define CP_GOST_R3410_2012_512_ALGORITHM	"GOST R 34.10-2012 512"
#define CP_GOST_R3410EL_DH_ALGORITHM		"GOST R 34.10-2001 256 DH"
#define CP_GOST_R3410_2012_256_DH_ALGORITHM	"GOST R 34.10-2012 256 DH"
#define CP_GOST_R3410_2012_512_DH_ALGORITHM	"GOST R 34.10-2012 512 DH"
#define CP_CHAINING_MODE_CTR			"ChainingModeCTR"
#define CP_CHAINING_MODE_OMAC_CTR		"ChainingModeOMAC_CTR"
#define CP_CHAINING_MODE_CNT			"ChainingModeCNT"

#define CP_PRIMITIVE_PROVIDER			L"Crypto-Pro Primitive Provider"

#define CONCAT_L_INTERNAL(x) L##x
#define CAT_L(x) CONCAT_L_INTERNAL(x)

#define BCRYPT_CP_GOST_R3411_ALGORITHM		    CAT_L(CP_GOST_R3411_ALG)
#define BCRYPT_CP_GOST_28147_ALGORITHM		    CAT_L(CP_GOST_28147_ALG)
#define BCRYPT_CP_GOST_R3411_2012_256_ALGORITHM	    CAT_L(CP_GOST_R3411_2012_256_ALG)
#define BCRYPT_CP_GOST_R3411_2012_512_ALGORITHM	    CAT_L(CP_GOST_R3411_2012_512_ALG)
#define BCRYPT_CP_GOST_R3411_256_ALGORITHM	    L"GR 34.11/256"
#define BCRYPT_CP_GOST_R3411_512_ALGORITHM	    L"GR 34.11/512"
#define BCRYPT_CP_GOST_R3410EL_ALGORITHM	    L"GR 34.10-2001"	/*Do not change legacy algs names (PP_ENUMALGS)*/
#define BCRYPT_CP_GOST_R3410_2012_256_ALGORITHM	    CAT_L(CP_GOST_R3410_2012_256_ALG)
#define BCRYPT_CP_GOST_R3410_2012_512_ALGORITHM	    CAT_L(CP_GOST_R3410_2012_512_ALG)
#define BCRYPT_CP_GOST_R3410_256_ALGORITHM	    L"GR 34.10/512"
#define BCRYPT_CP_GOST_R3410_512_ALGORITHM	    L"GR 34.10/1024"
#define BCRYPT_CP_GOST_R3410EL_DH_ALGORITHM	    L"GOST " CAT_L(CP_GOST_R3410EL_DH_ALG)
#define BCRYPT_CP_GOST_R3410_2012_256_DH_ALGORITHM  L"GOST " CAT_L(CP_GOST_R3410_2012_256_DH_ALG)
#define BCRYPT_CP_GOST_R3410_2012_512_DH_ALGORITHM  L"GOST " CAT_L( CP_GOST_R3410_2012_512_DH_ALG)
#define BCRYPT_CP_GOST_R3412_M_ALGORITHM	    CAT_L(CP_GOST_R3412_2015_M_ALG)
#define BCRYPT_CP_GOST_R3412_K_ALGORITHM	    CAT_L(CP_GOST_R3412_2015_K_ALG)
#define BCRYPT_CP_CHAINING_MODE_CTR		    CAT_L(CP_CHAINING_MODE_CTR)
#define BCRYPT_CP_CHAINING_MODE_OMAC_CTR	    CAT_L(CP_CHAINING_MODE_OMAC_CTR)
#define BCRYPT_CP_CHAINING_MODE_CNT		    CAT_L(CP_CHAINING_MODE_CNT)
#define BCRYPT_ALGID				    L"Algorithm"
#define BCRYPT_CIPHEROID			    L"CipherOID"
#define BCRYPT_DHOID				    L"DiffieHellmanOID"
#define BCRYPT_HASHOID				    L"HashOID"

#define NCRYPT_VERSION_EX_PROPERTY		    L"VersionEx"
#define NCRYPT_DHOID_PROPERTY			    L"DiffieHellmanOID"

#define KDF_UKM					    0x80000001

/* Режим блочного шифрования с обратной связью на базе ГОСТ 28147-89, шифр-текст блока всегда является IV для следующего.*/
/*! \ingroup ProCSPData
*  \brief Режим блочного шифрования с обратной связью на базе ГОСТ 28147-89, шифр-текст блока всегда является IV для следующего
*/
#define CRYPT_MODE_CBCSTRICT	1 

/* Режим блочного шифрования с обратной связью на базе ГОСТ 28147-89, согласно RFC 4357.*/
/*! \ingroup ProCSPData
*  \brief Режим блочного шифрования с обратной связью на базе ГОСТ 28147-89, согласно RFC 4357
*/
#define CRYPT_MODE_CBCRFC4357	31 

/* Режим шифрования "гаммирование" по ГОСТ 28147-89.*/
/*! \ingroup ProCSPData
 *  \brief Режим шифрования "гаммированием" по ГОСТ 28147-89
 */
#define CRYPT_MODE_CNT          3      // GOST 28147-89 in "gammirovanie" (counter) mode

/* Режим шифрования "гаммирование" по ГОСТ Р 34.13-2015.*/
/*! \ingroup ProCSPData
*  \brief Режим шифрования "гаммирование" по ГОСТ Р 34.13-2015
*/
#define CRYPT_MODE_CTR          32

/* Режим аутентифицированного шифрования MGM согласно рекомендациям по стандартизации Р 1323565.1.026-2019 "Режимы работы блочных шифров, реализующие аутентифицированное шифрование" */
/*! \ingroup ProCSPData
*  \brief Режим аутентифицированного шифрования MGM согласно рекомендациям по стандартизации Р 1323565.1.026-2019 "Режимы работы блочных шифров, реализующие аутентифицированное шифрование"
*/
#define CRYPT_MODE_MGM          33

#define CRYPT_MODE_GCM          34

#define CRYPT_MODE_OMAC_CTR	35

#define CRYPT_MODE_WRAP		36

#define CRYPT_MODE_WRAP_PAD	37

/* Длина секретного ключа для ГОСТ 28147-89, подписи и обмена.*/
/*! \ingroup ProCSPData
 *  \brief Длина в байтах ключей ГОСТ 28147-89, ГОСТ Р 34.12-2015 Магма и Кузнечик
 * и закрытых ключей ГОСТ Р 34.10-2001.
 */
#define SECRET_KEY_LEN		32
#define SECRET_KEY_BITLEN	256

#define SYMMETRIC_KEY_512_LEN		64
#define SYMMETRIC_KEY_512_BITLEN	512

#define FOREIGN_TLS_PREMASTER_KEY_LEN	    48
#define FOREIGN_TLS_PREMASTER_KEY_BITLEN    384

#define SCHANNEL_PRF_ALG		2
#define SCHANNEL_HASH_ALG		3

/*! \ingroup ProCSPData
 *  \brief Длина в байтах ключа ГОСТ 28147-89
 * \sa SECRET_KEY_LEN
 */
#define G28147_KEYLEN        SECRET_KEY_LEN

/*! \ingroup ProCSPData
 *  \brief Длина в байтах имитовставки при импорте/экспорте
 */
#define EXPORT_IMIT_SIZE		4

/*! \ingroup ProCSPData
 *  \brief Длина в байтах имитовставки при импорте/экспорте по алгоритму CALG_SIMPLE_EXPORT_K
 */
#define SIMPLE_EXPORT_K_IMIT_SIZE	8

/*! \ingroup ProCSPData
 *  \brief Длина в байтах контрольной величины ключа при импорте и получении параметра ключа
 */
#define CHECK_VALUE_SIZE		3
/*! \ingroup ProCSPData
 *  \brief Длина  в байтах вектора инициализации алгоритма
 */
#define SEANCE_VECTOR_LEN		8

/*! \ingroup ProCSPData
*  \brief Максимальная разрешённая длина имени ключевого контейнера (без терминального символа).
*/
#define MAX_CONTAINER_NAME_LEN		260

/*! \ingroup ProCSPData
*  \brief Максимальная разрешённая длина имени папки ключевого контейнера (без терминального символа).
*/
#define MAX_FOLDER_NAME_LEN		MAX_CONTAINER_NAME_LEN

/*! \ingroup ProCSPData
*  \brief Максимальная разрешённая длина уникального имени носителя (без терминального символа).
*/
#define MAX_UNIQUE_LEN			256

/*! \ingroup ProCSPData
*  \brief Максимальная разрешённая длина типа носителя (без терминального символа).
*/
#define MAX_MEDIA_TYPE_NAME_LEN		64

/*! \ingroup ProCSPData
*  \brief Максимальная разрешённая длина имени считывателя (без терминального символа).
*/
#define MAX_READER_NAME_LEN		255

/*! \ingroup ProCSPData
*  \brief Длина CRC.
*/
#define CONTAINER_CRC_LEN 4

/*! \ingroup ProCSPData
*  \brief Максимальная разрешённая длина входной строки, определяющей контейнер, в CryptAcquireContext (без терминального символа).
*/
#define MAX_INPUT_CONTAINER_STRING_LEN	(4 + MAX_READER_NAME_LEN + 1 + MAX_MEDIA_TYPE_NAME_LEN + 1 + MAX_UNIQUE_LEN + MAX_FOLDER_NAME_LEN + 1 + CONTAINER_CRC_LEN)


/* Константы и структуры для схем цифровой подписи и*/
/* открытого распределения ключей*/

/*! \ingroup ProCSPData
 *  \brief Признак ключа ГОСТ Р 34.10-2001
 */
#define GR3410_1_MAGIC			0x3147414D
#define GR3410_2_MAGIC			GR3410_1_MAGIC//0x3145474a

#define DH_1_MAGIC			GR3410_1_MAGIC
#define DH_2_MAGIC			GR3410_1_MAGIC
#define DH_3_MAGIC			GR3410_1_MAGIC

/*! \ingroup ProCSPData
 *  \brief Признак ключей ГОСТ 28147-89 и мастер ключей TLS
 */
#define G28147_MAGIC			0x374a51fd
#define SIMPLEBLOB_MAGIC		G28147_MAGIC
#define G28147_OPAQUEMAGIC		0x374a51fe
/*! \ingroup ProCSPData
 *  \brief Признак ключевого блоба функции диверсификации ключа
 */
#define DIVERS_MAGIC			0x31564944

/*! \ingroup ProCSPData
*  \brief Признак ключевого блоба алгоритма KExp15
*/
#define KEXP15_MAGIC			0x374a51ff

#define EDDSA_MAGIC			0x374a5200
#define CV25519_MAGIC			EDDSA_MAGIC

/*! \ingroup ProCSPData
 *  \brief Текущее значение версии ключевого блоба
 */
#define BLOB_VERSION			(BYTE)0x20

/*! \ingroup ProCSPData
*  \brief Текущее значение версии ключевого блоба KExp15
*/
#define KEXP15_BLOB_VERSION		(BYTE)0x21

#define RSA1_MAGIC			0x31415352
#define RSA2_MAGIC			0x32415352

/*! \ingroup ProCSPData
*  \brief Флаг, устанавливающий признак получения открытого ключа из сертификата
*/
#define CP_CRYPT_PUBLICKEY_FROM_CERT	(0x00010000)
#define CERT_MAGIC			(0xbeef)

/*! \ingroup ProCSPData
*  \brief Тип блопа симметричного ключа для функций BCrypt(Import/Export)Key
*/
#define BCRYPT_SIMPLEBLOB		L"SIMPLEBLOB"
#define BCRYPT_SIMPLEBLOB_MAGIC		0x374a5201

/* Определения для */
/*! \ingroup ProCSPData
 * \brief Отладочная версия дистрибутива.
 */
#define VER_TYPE_DEBUG 1
/*! \ingroup ProCSPData
* \brief Релизная версия дистрибутива.
*/
#define VER_TYPE_RELEASE 0

/*! \ingroup ProCSPData
* \brief Архитектура IA32.
*/
#define VER_ARCH_IA32	    0
/*! \ingroup ProCSPData
* \brief Архитектура IA64.
*/
#define VER_ARCH_IA64	    1
/*! \ingroup ProCSPData
* \brief Архитектура Sparc32.
*/
#define VER_ARCH_SPARC32    2
/*! \ingroup ProCSPData
* \brief Архитектура Sparc64.
*/
#define VER_ARCH_SPARC64    3
/*! \ingroup ProCSPData
* \brief Архитектура AMD64.
*/
#define VER_ARCH_AMD64	    4
/*! \ingroup ProCSPData
* \brief Архитектура ARM.
*/
#define VER_ARCH_ARM	    5
/*! \ingroup ProCSPData
* \brief Архитектура PowerPC32.
*/
#define VER_ARCH_PPC32      6
/*! \ingroup ProCSPData
* \brief Архитектура PowerPC64.
*/
#define VER_ARCH_PPC64      7
/*! \ingroup ProCSPData
* \brief Архитектура ARM64.
*/
#define VER_ARCH_ARM64	    8
/*! \ingroup ProCSPData
* \brief Архитектура MIPS32.
*/
#define VER_ARCH_MIPS32	    9
/*! \ingroup ProCSPData
* \brief Архитектура Эльбрус 32.
*/
#define VER_ARCH_E2K32	    10

/*! \ingroup ProCSPData
* \brief Архитектура Эльбрус 64.
*/
#define VER_ARCH_E2K64	    11

/*! \ingroup ProCSPData
* \brief Архитектура RISCV64
*/
#define VER_ARCH_RISCV64    12


/*! \ingroup ProCSPData
* \brief ОС Windows.
*/
#define VER_OS_WINDOWS 0
/*! \ingroup ProCSPData
* \brief ОС Solaris.
*/
#define VER_OS_SOLARIS 1
/*! \ingroup ProCSPData
* \brief ОС FreeBSD.
*/
#define VER_OS_FREEBSD 2
/*! \ingroup ProCSPData
* \brief ОС Linux.
*/
#define VER_OS_LINUX   3
/*! \ingroup ProCSPData
* \brief ОС AIX.
*/
#define VER_OS_AIX     4

/*! \ingroup ProCSPData
* \brief ОС Mac OS X.
*/
#define VER_OS_DARWIN  5
/*! \ingroup ProCSPData
* \brief Apple iOS */
#define VER_OS_IOS  6
/*! \ingroup ProCSPData
* \brief ANDROID OS */
#define VER_OS_ANDROID 7
/*! \ingroup ProCSPData
* \brief BITVISOR_OS */
#define VER_OS_BITVISOR 8
/*! \ingroup ProCSPData
* \brief UCLIBC runtime
*/
#define VER_OS_UCLIBC 9

/*! \ingroup ProCSPData
 *
 * \brief Структура описывает версию СКЗИ, ПКЗИ, тип сборки,
 * аппаратную архитектуру и ОС, для которой предназначен продукт.
 */
typedef struct _PROV_PP_VERSION_EX {
    DWORD PKZI_Build;	/*!< Версия ПКЗИ. */
    DWORD SKZI_Build;	/*!< Версия СКЗИ. */
    DWORD TypeDebRel;	/*!< Тип сборки: VER_TYPE_DEBUG, VER_TYPE_RELEASE. */
    DWORD Architecture;	/*!< Аппаратная архитектура: VER_ARCH_IA32, 
			 * VER_ARCH_IA64, VER_ARCH_SPARC32, VER_ARCH_SPARC64,
			 * VER_ARCH_AMD64, VER_ARCH_ARM, VER_ARCH_ARM64,
			 * VER_ARCH_PPC32, VER_ARCH_PPC64, VER_ARCH_MIPS32,
			 * VER_ARCH_E2K32, VER_ARCH_E2K64, VER_ARCH_RISCV64.
			 */
    DWORD OS;		/*!< Тип ОС: VER_OS_WINDOWS, VER_OS_SOLARIS,
			 * VER_OS_FREEBSD, VER_OS_LINUX, VER_OS_AIX,
			 * VER_OS_DARWIN, VER_OS_IOS, VER_OS_ANDROID,
			 * VER_OS_BITVISOR, VER_OS_UCLIBC.
			 */
} PROV_PP_VERSION_EX;

/*! \ingroup ProCSPData
 *
 * \brief Заголовок результата встроенного тестирования и контроля 
 *        целостности СКЗИ.
 */
typedef struct _SELFTEST_HEADER {
    DWORD PKZI_Build;	  /*!< Версия ПКЗИ. */
    DWORD SKZI_Build;	  /*!< Версия СКЗИ. */
    DWORD TypeDebRel;	  /*!< Тип сборки: VER_TYPE_DEBUG, VER_TYPE_RELEASE. */
    DWORD Architecture;	  /*!< Аппаратная архитектура: VER_ARCH_IA32, 
			   * VER_ARCH_IA64, VER_ARCH_SPARC32, VER_ARCH_SPARC64,
			   * VER_ARCH_AMD64, VER_ARCH_ARM, VER_ARCH_ARM64,
			   * VER_ARCH_PPC32, VER_ARCH_PPC64.
			   */
    DWORD OS;		  /*!< Тип ОС: VER_OS_WINDOWS, VER_OS_SOLARIS,
			   * VER_OS_FREEBSD, VER_OS_LINUX, VER_OS_AIX.
			   */
    DWORD TesterFlags;	  /*!< Битовый вектор ошибок встроенных тестов, 
			   * включает результат контроля целостности.
			   * В случае успеха, должен быть равен 0.
			   */
    DWORD TotalChecksums; /*!< Количество модулей, информация о которых 
			   * была записана в поле Checksums структуры 
			   * PROV_PP_SELFTEST.
			   */
    DWORD UnwrittenChecksums; 
			  /*!< Количество модулей, информация о которых
			   * не была записана в поле Checksums структуры 
			   * PROV_PP_SELFTEST по причине недостаточного
			   * количества памяти, выделенной для структуры.
			   * Если памяти достаточно, равно 0. */
} SELFTEST_HEADER;

/*! \ingroup ProCSPData
*
* \brief Структура описывает время работы (тики) процессора в простое,
*  режиме ядра, пользовательском режиме, Nice режиме, и полное время работы процессора
*/
typedef struct _CPU_INFO {
    ULONGLONG Idle;  // Время в режиме простоя
    ULONGLONG Kernel; // Время в режиме ядра
    ULONGLONG User; // Время в пользовательском режиме
    ULONGLONG Nice; // Время в режиме Nice
    DWORD dwProcNumber; // Количество ядер процессора
    DWORD Dummy;	// Для выравнивания байт
} CPU_INFO;

/*! \ingroup ProCSPData
 *
 * \brief Результат контроля целостности модуля.
 */
typedef struct _SELFTEST_CHECKSUM_ELEMENT {
    char BlockName[40];		/*!< Название модуля. */
    BYTE InitialHash[32];	/*!< Эталонная контрольная сумма. */
    BYTE CalculatedHash[32];	/*!< Фактическая контрольная сумма. */
} SELFTEST_CHECKSUM_ELEMENT;

/*! \ingroup ProCSPData
 *
 * \brief Результат встроенного тестирования и контроля 
 *        целостности СКЗИ.
 */
typedef struct _PROV_PP_SELFTEST {
    SELFTEST_HEADER Header;	/*!< Заголовок \ref SELFTEST_HEADER. */
    SELFTEST_CHECKSUM_ELEMENT Checksums[1];
				/*!< Массив \ref SELFTEST_CHECKSUM_ELEMENT 
				 * размера Header.TotalChecksums. 
				 */
} PROV_PP_SELFTEST;

/* Определения для структуры SIMPLEBLOB*/
/* Заголовок SIMPLEBLOB*/
/*!
 * \ingroup ProCSPData
 *
 * \brief Структура CRYPT_SIMPLEBLOB_HEADER является расширением структуры BLOBHEADER и
 * находится в начале поля \b pbData ключевого блоба типа SIMPLEBLOB для ключей "КриптоПро CSP".
 *
 * \req_wincryptex
 * \sa _PUBLICKEYSTRUC
 * \sa PCRYPT_SIMPLEBLOB
 * \sa CPExportKey
 * \sa CPGetKeyParam
 */
typedef struct _CRYPT_SIMPLEBLOB_HEADER {
    BLOBHEADER BlobHeader;
                    /*!< Общий заголовок ключевого блоба. Определяет алгоритм ключа
                     * находящегося в ключевом блобе. См. \ref _PUBLICKEYSTRUC.
                     */
    DWORD Magic;
                    /*!< Признак ключей по ГОСТ 28147-89 или мастер ключей TLS,
                     * устанавливается в \ref G28147_MAGIC.
                     */
    ALG_ID EncryptKeyAlgId;
                    /*!< Определяет алгоритм экспорта ключа. Этот алгоритм является
                     * параметром ключа экспорта. См. \ref #CPGetKeyParam.
                     */
} CRYPT_SIMPLEBLOB_HEADER;
/*!
 * \ingroup ProCSPData
 *
 * \brief Псевдоструктура (т. е. недоопределенная структура) CRYPT_SIMPLEBLOB полностью описывает ключевой блоб
 * типа SIMPLEBLOB для ключей "КриптоПро CSP". 
 *
 * \req_wincryptex
 * \sa CRYPT_SIMPLEBLOB_HEADER
 * \sa CPExportKey
 * \sa CPGetKeyParam
 */
typedef struct _CRYPT_SIMPLEBLOB {
    CRYPT_SIMPLEBLOB_HEADER tSimpleBlobHeader;
                    /*!< Общий заголовок ключевого блоба типа SIMPLEBLOB "КриптоПро CSP".
                     */
    BYTE    bSV[SEANCE_VECTOR_LEN];
                    /*!< Вектор инициализации для алгоритма CALG_PRO_EXPORT.
                     * См. \ref SEANCE_VECTOR_LEN.
                     */
    BYTE    bEncryptedKey[G28147_KEYLEN];
                    /*!< Зашифрованный ключ ГОСТ 28147-89.
                     * См. \ref G28147_KEYLEN.
                     */
    BYTE    bMacKey[EXPORT_IMIT_SIZE];
                    /*!< Имитовставка по ГОСТ 28147-89 на ключ. Рассчитывается
                     * до зашифрования и проверяется после расшифрования.
                     * См. \ref EXPORT_IMIT_SIZE.
                     */
    BYTE    bEncryptionParamSet[1];
                    /*!< Содержит ASN1 структуру в DER кодировке, определяющую
                     * параметры алгоритма шифрования ГОСТ 28147-89:
                     * \code
                     *      encryptionParamSet
                     *          OBJECT IDENTIFIER (
                     *              id-Gost28147-89-TestParamSet |      -- Only for tests use
                     *              id-Gost28147-89-CryptoPro-A-ParamSet |
                     *              id-Gost28147-89-CryptoPro-B-ParamSet |
                     *              id-Gost28147-89-CryptoPro-C-ParamSet |
                     *              id-Gost28147-89-CryptoPro-D-ParamSet |
                     *              id-Gost28147-89-CryptoPro-Simple-A-ParamSet |
                     *              id-Gost28147-89-CryptoPro-Simple-B-ParamSet |
                     *              id-Gost28147-89-CryptoPro-Simple-C-ParamSet |
                     *              id-Gost28147-89-CryptoPro-Simple-D-ParamSet
                     * \endcode
                     */
}   CRYPT_SIMPLEBLOB, *PCRYPT_SIMPLEBLOB;
/*!
 * \ingroup ProCSPData
 *
 * \brief Псевдоструктура (т. е. недоопределенная структура) CRYPT_SIMPLEBLOB_K полностью описывает ключевой блоб
 * типа SIMPLEBLOB для ключей "КриптоПро CSP",
 * зашифрованных с использованием ключа ГОСТ Р 34.12-2015 с длиной блока 128 бит ("Кузнечик").
 *
 * \req_wincryptex
 * \sa CRYPT_SIMPLEBLOB_HEADER
 * \sa CPExportKey
 * \sa CPGetKeyParam
 */
typedef struct _CRYPT_SIMPLEBLOB_K {
    CRYPT_SIMPLEBLOB_HEADER tSimpleBlobHeader;
    /*!< Общий заголовок ключевого блоба типа SIMPLEBLOB "КриптоПро CSP".
     */
    BYTE    bSV[SEANCE_VECTOR_LEN];
    /*!< Вектор инициализации не используется и всегда заполнен нулевыми байтами.
     * См. \ref SEANCE_VECTOR_LEN.
     */
    BYTE    bEncryptedKey[G28147_KEYLEN];
    /*!< Зашифрованный ключ ГОСТ 28147-89 или ГОСТ Р 34.12-2015 с длиной блока 128 или 64 бит ("Кузнечик" или "Магма").
     * См. \ref G28147_KEYLEN.
     */
    BYTE    bMacKey[SIMPLE_EXPORT_K_IMIT_SIZE];
    /*!< Имитовставка длины SIMPLE_EXPORT_K_IMIT_SIZE по ГОСТ Р 34.13-2015 на ключ. Рассчитывается
     * до зашифрования и проверяется после расшифрования.
     * См. \ref SIMPLE_EXPORT_K_IMIT_SIZE.
     */
    BYTE    bEncryptionParamSet[1];
    /*!< Содержит ASN1 структуру в DER кодировке, определяющую
     * параметры алгоритма шифрования зашифрованного ключа:
     * \code
     *      encryptionParamSet
     *          OBJECT IDENTIFIER (
     *              id-Gost28147-89-TestParamSet |      -- Only for tests use
     *              id-Gost28147-89-CryptoPro-A-ParamSet |
     *              id-Gost28147-89-CryptoPro-B-ParamSet |
     *              id-Gost28147-89-CryptoPro-C-ParamSet |
     *              id-Gost28147-89-CryptoPro-D-ParamSet |
     *              id-Gost28147-89-CryptoPro-Simple-A-ParamSet |
     *              id-Gost28147-89-CryptoPro-Simple-B-ParamSet |
     *              id-Gost28147-89-CryptoPro-Simple-C-ParamSet |
     *              id-Gost28147-89-CryptoPro-Simple-D-ParamSet
     * \endcode
     */
}   CRYPT_SIMPLEBLOB_K, * PCRYPT_SIMPLEBLOB_K;
/*!
* \ingroup ProCSPData
*
* \brief Псевдоструктура (т. е. недоопределенная структура) CRYPT_SIMPLEBLOB полностью описывает ключевой блоб
* типа SIMPLEBLOB для ключей "КриптоПро CSP".
*
* \req_wincryptex
* \sa CRYPT_SIMPLEBLOB_HEADER
* \sa CPExportKey
* \sa CPGetKeyParam
*/
typedef struct _CRYPT_SIMPLEBLOB_512 {
    CRYPT_SIMPLEBLOB_HEADER tSimpleBlobHeader;
    /*!< Общий заголовок ключевого блоба типа SIMPLEBLOB "КриптоПро CSP".
    */
    BYTE    bSV[SEANCE_VECTOR_LEN];
    /*!< Вектор инициализации для алгоритма CALG_PRO_EXPORT.
    * См. \ref SEANCE_VECTOR_LEN.
    */
    BYTE    bEncryptedKey[SYMMETRIC_KEY_512_LEN];
    /*!< Зашифрованный ключ CALG_SYMMETRIC_512.
    * См. \ref G28147_KEYLEN.
    */
    BYTE    bMacKey[EXPORT_IMIT_SIZE];
    /*!< Имитовставка по ГОСТ 28147-89 на ключ. Рассчитывается
    * до зашифрования и проверяется после расшифрования.
    * См. \ref EXPORT_IMIT_SIZE.
    */
    BYTE    bEncryptionParamSet[1];
    /*!< Содержит ASN1 структуру в DER кодировке, определяющую
    * параметры алгоритма шифрования ГОСТ 28147-89:
    * \code
    *      encryptionParamSet
    *          OBJECT IDENTIFIER (
    *              id-Gost28147-89-TestParamSet |      -- Only for tests use
    *              id-Gost28147-89-CryptoPro-A-ParamSet |
    *              id-Gost28147-89-CryptoPro-B-ParamSet |
    *              id-Gost28147-89-CryptoPro-C-ParamSet |
    *              id-Gost28147-89-CryptoPro-D-ParamSet |
    *              id-Gost28147-89-CryptoPro-Simple-A-ParamSet |
    *              id-Gost28147-89-CryptoPro-Simple-B-ParamSet |
    *              id-Gost28147-89-CryptoPro-Simple-C-ParamSet |
    *              id-Gost28147-89-CryptoPro-Simple-D-ParamSet
    * \endcode
    */
}   CRYPT_SIMPLEBLOB_512, *PCRYPT_SIMPLEBLOB_512;


/*!
* \ingroup ProCSPData
*
* \brief Псевдоструктура (т. е. недоопределенная структура) CRYPT_SIMPLEBLOB_KEXP15 полностью описывает ключевой блоб
* типа SIMPLEBLOB при использовании алгоритма KEXP15 для экспорта ключей "КриптоПро CSP".
* В поле tSimpleBlobHeader.BlobHeader.bVersion должна быть указана константа KEXP15_BLOB_VERSION.
* В поле tSimpleBlobHeader.Magic должен быть указан KEXP15_MAGIC.
*
* \req_wincryptex
* \sa CRYPT_SIMPLEBLOB_HEADER
* \sa CPExportKey
* \sa CPImportKey
*/
typedef struct _CRYPT_SIMPLEBLOB_KEXP15 {
    CRYPT_SIMPLEBLOB_HEADER tSimpleBlobHeader;
    /*!< Общий заголовок ключевого блоба типа SIMPLEBLOB "КриптоПро CSP".
    */
    BYTE    bEncryptedKey[1];
    /*!< Содержит ASN1 структуру в DER кодировке, содержащую зашифрованный ключ:
    * \code
    *    GostKeyTransportKExp15 ::= SEQUENCE {
    *		ukm                       OCTET STRING,
    *		encryptedKeyData          OCTET STRING,
    *		encryptedMac              OCTET STRING
    *    }
    * \endcode
    */
}   CRYPT_SIMPLEBLOB_KEXP15, *PCRYPT_SIMPLEBLOB_KEXP15;

/*!
 * \ingroup ProCSPData
 *
 * \brief Псевдоструктура (т. е. недоопределенная структура) CRYPT_OPAQUEBLOB полностью описывает ключевой блоб
 * типа OPAQUEKEYLOB для ключей "КриптоПро CSP". 
 *
 * \req_wincryptex
 * \sa CRYPT_SIMPLEBLOB_HEADER
 * \sa CPExportKey
 * \sa CPImportKey
 */
typedef struct _CRYPT_OPAQUEBLOB {
    CRYPT_SIMPLEBLOB_HEADER tSimpleBlobHeader;
                    /*!< Общий заголовок ключевого блоба типа SIMPLEBLOB "КриптоПро CSP".
                     */
    BYTE    bSV[SEANCE_VECTOR_LEN];
                    /*!< Вектор инициализации для алгоритма CALG_PRO_EXPORT.
                     * См. \ref SEANCE_VECTOR_LEN.
                     */
    BYTE    bEncryptedKey[G28147_KEYLEN];
                    /*!< Зашифрованный ключ ГОСТ 28147-89.
                     * См. \ref G28147_KEYLEN.
                     */
    BYTE    bMacKey[EXPORT_IMIT_SIZE];
                    /*!< Имитовставка по ГОСТ 28147-89 на ключ. Рассчитывается
                     * до зашифрования и проверяется после расшифрования.
                     * См. \ref EXPORT_IMIT_SIZE.
                     */
    BYTE    bEncryptedInitKey[G28147_KEYLEN];
                    /*!< Зашифрованный ключ ГОСТ 28147-89.
                     * См. \ref G28147_KEYLEN.
                     */
    BYTE    bMacInitKey[EXPORT_IMIT_SIZE];
                    /*!< Имитовставка по ГОСТ 28147-89 на ключ. Рассчитывается
                     * до зашифрования и проверяется после расшифрования.
                     * См. \ref EXPORT_IMIT_SIZE.
                     */
      /*Не шифруемые поля*/
   BYTE    bCurrentIV[SEANCE_VECTOR_LEN];
                    /*!< Вектор инициализации шифратора.
                     * См. \ref SEANCE_VECTOR_LEN.
                     */
    BYTE    bChainBlock[8];
                    /*!< Блок зацепления. Использование блока зависит от режима шифрования.
                     *
                     */
    BYTE    bAccCiphertextLen[sizeof(DWORD)];
                    /*!< Накопленная длина шифрованного текста в текущем шифровании.
                     *
                     */
    BYTE    bCommAccCiphertextLen[sizeof(DWORD)];
                    /*!< Накопленная длина шифрованного текста после финализаций.
                     *
                     */
    BYTE    bCommCipherTextLenOnBaseKey[sizeof(DWORD)];
                    /*!< Накопленная нагрузка на базовый ключ.
                     *
                     */
    BYTE    bCipherMode[sizeof(DWORD)];
    BYTE    bMixMode[sizeof(DWORD)];
    BYTE    bFlags[4];
    BYTE    bPaddingMode[sizeof(DWORD)];
    BYTE    bAlgId[sizeof(ALG_ID)];
    BYTE    bCommonFlags[4];
    BYTE    bCheckSum[sizeof(DWORD)];
    BYTE    bEncryptionParamSet[1];
                    /*!< Содержит ASN1 структуру в DER кодировке, определяющую
                     * параметры алгоритма шифрования ГОСТ 28147-89:
                     * \code
                     *      encryptionParamSet
                     *          OBJECT IDENTIFIER (
                     *              id-Gost28147-89-TestParamSet |      -- Only for tests use
                     *              id-Gost28147-89-CryptoPro-A-ParamSet |
                     *              id-Gost28147-89-CryptoPro-B-ParamSet |
                     *              id-Gost28147-89-CryptoPro-C-ParamSet |
                     *              id-Gost28147-89-CryptoPro-D-ParamSet |
                     *              id-Gost28147-89-CryptoPro-Simple-A-ParamSet |
                     *              id-Gost28147-89-CryptoPro-Simple-B-ParamSet |
                     *              id-Gost28147-89-CryptoPro-Simple-C-ParamSet |
                     *              id-Gost28147-89-CryptoPro-Simple-D-ParamSet
                     * \endcode
                     */
}   CRYPT_OPAQUEBLOB, *PCRYPT_OPAQUEBLOB;


typedef struct _CRYPT_OPAQUEHASHBLOB {
    CRYPT_SIMPLEBLOB_HEADER tSimpleBlobHeader;
                    /*!< Общий заголовок ключевого блоба типа SIMPLEBLOB "КриптоПро CSP".
                     */
   BYTE    ImitVal[8];
   BYTE    bCurrKey[G28147_KEYLEN];
                    /*!< ключ ГОСТ 28147-89.
                     * См. \ref G28147_KEYLEN.
                     */
    BYTE    bChainBlock[8];
                    /*!< Блок зацепления. Использование блока зависит от режима шифрования.
                     *
                     */
    BYTE    bAccCiphertextLen[sizeof(DWORD)];
                    /*!< Накопленная длина шифрованного текста в текущем шифровании.
                     *
                     */
    BYTE    bCommAccCiphertextLen[sizeof(DWORD)];
                    /*!< Накопленная длина шифрованного текста после финализаций.
                     *
                     */
    BYTE    bCommCipherTextLenOnBaseKey[sizeof(DWORD)];
                    /*!< Накопленная нагрузка на базовый ключ.
                     *
                     */
    BYTE    bHFlags[4];
    BYTE    bCheckSum[sizeof(DWORD)];
}   CRYPT_OPAQUEHASHBLOB;


/*!
 * \ingroup ProCSPData
 *
 * \brief Структура CRYPT_PUBKEYPARAM содержит признак ключей
 * по ГОСТ Р 34.10-2001.
 *
 * \req_wincryptex
 * \sa CRYPT_PUBKEY_INFO_HEADER
 * \sa CPExportKey
 * \sa CPGetKeyParam
 */
typedef struct _CRYPT_PUBKEYPARAM {
    DWORD Magic;
                    /*!< Признак ключей по ГОСТ Р 34.10-2001
                     * устанавливается в \ref GR3410_1_MAGIC.
                     */
    DWORD BitLen;
                    /*!< Длина открытого ключа в битах.
                     */
} CRYPT_PUBKEYPARAM, *LPCRYPT_PUBKEYPARAM;

/* Заголовок PUBLICKEYBLOB и PRIVATEKEYBLOB*/
/*!
 * \ingroup ProCSPData
 *
 * \brief Структура CRYPT_PUBKEY_INFO_HEADER содержит заголовок
 * блоба открытого ключа или блоба ключевой пары
 * по ГОСТ Р 34.10-2001 или ГОСТ Р 34.10-2012.
 *
 * \req_wincryptex
 * \sa _PUBLICKEYSTRUC
 * \sa CRYPT_PUBKEYPARAM
 * \sa CPExportKey
 * \sa CPGetKeyParam
 */
typedef struct _CRYPT_PUBKEY_INFO_HEADER {
    BLOBHEADER BlobHeader;
                    /*!< Общий заголовок ключевого блоба. Определяет его тип и алгоритм ключа
                     * находящегося в ключевом блобе. Для открытых ключей алгоритм
                     * ключа всегда CALG_GR3410, CALG_GR3410EL, CALG_GR3410_12_256
		     * или CALG_GR3410_12_512. Для ключевых
                     * пар алгоритм отражает её назначение. См. \ref _PUBLICKEYSTRUC.
                     */
    CRYPT_PUBKEYPARAM KeyParam;
                    /*!< Основной признак и длина ключей ГОСТ Р 34.10-2001 и ГОСТ Р 34.10-2012.
                     */
} CRYPT_PUBKEY_INFO_HEADER;

/*!
 * \ingroup ProCSPData
 *
 * \brief Псевдоструктура CRYPT_PUBLICKEYBLOB полностью описывает ключевой блоб
 * типа PUBLICKEYBLOB для ключей "КриптоПро CSP". 
 *
 * \req_wincryptex
 * \sa CRYPT_PUBKEY_INFO_HEADER
 * \sa CPExportKey
 * \sa CPGetKeyParam
 */
typedef struct _CRYPT_PUBLICKEYBLOB {
    CRYPT_PUBKEY_INFO_HEADER tPublicKeyParam;
                    /*!< Общий заголовок ключевого блоба типа PUBLICKEYBLOB "КриптоПро CSP".
                     */
    BYTE    bASN1GostR3410_2001_PublicKeyParameters[1/*псевдомассив*/];
                    /*!< Содержит ASN1 структуру в DER кодировке, определяющую
                     * параметры открытого ключа.
		     * Для ключей ГОСТ Р 34.10-2001 параметры описаны
                     * типом GostR3410-2001-PublicKeyParameters
                     * CPPK [RFC 4491] и CPALGS [RFC 4357].
		     * Для ключей ГОСТ Р 34.10-2012 параметры описаны
		     * типом GostR3410-2012-PublicKeyParameters
		     * в соответствии со структурой, описанной в п. 5.2.1.2
		     * Р 1323565.1.023-2018.
                     */
    BYTE    bPublicKey[1/*псевдомассив*/];
                    /*!< Содержит открытый ключ.
                     * Для ключей ГОСТ Р 34.10-2001, как описано типом GostR3410-2001-PublicKey
                     * CPPK [RFC 4491].
		     * Для ключей ГОСТ Р 34.10-2012 с длиной ключа 256 бит, как описано
		     * типом GostR3410-2012-256-PublicKey, с длиной ключа 512 бит, как описано
		     * типом GostR3410-2012-512-PublicKey,
		     * в соответствии с описанием в п. 5.2.2
		     * Р 1323565.1.023-2018.
                     * Длина массива равна tPublicKeyParam.KeyParam.BitLen/8.
                     */
}   CRYPT_PUBLICKEYBLOB, *PCRYPT_PUBLICKEYBLOB;

/*!
 * \ingroup ProCSPData
 *
 * \brief Псевдоструктура CRYPT_PRIVATEKEYBLOB полностью описывает ключевой блоб
 * типа PRIVATEKEYBLOB для ключей "КриптоПро CSP".
 *
 * \req_wincryptex
 * \sa CRYPT_PUBKEY_INFO_HEADER
 * \sa CPExportKey
 * \sa CPGetKeyParam
 */
typedef struct _CRYPT_PRIVATEKEYBLOB {
    CRYPT_PUBKEY_INFO_HEADER tPublicKeyParam;
                    /*!< Общий заголовок ключевого блоба типа PRIVATEKEYBLOB "КриптоПро CSP".
                     */
    BYTE    bExportedKeys[1/* Псевдо массив.*/];
	/*
	KeyTransferContent ::=
	SEQUENCE {
	    encryptedPrivateKey  GostR3410EncryptedKey,
	    privateKeyParameters PrivateKeyParameters,
	}
	KeyTransfer ::=
	SEQUENCE {
	    keyTransferContent       KeyTransferContent,
	    hmacKeyTransferContent   Gost28147HMAC
	}
	*/
}   CRYPT_PRIVATEKEYBLOB, *PCRYPT_PRIVATEKEYBLOB;

/* Определения для структуры DIVERSBLOB*/
/*!
 * \ingroup ProCSPData
 *
 * \brief Структура CRYPT_DIVERSBLOBHEADER описывает блоб
 * типа DIVERSBLOB для процедуры диверсификации ключей КриптоПро CSP.
 *
 * \req_wincryptex
 * \sa CRYPT_DIVERSBLOB
 * \sa CPImportKey
 */
typedef struct _CRYPT_DIVERSBLOBHEADER {
    BLOBHEADER BlobHeader;
                /*!< Общий заголовок блоба, диверсифицирующего ключ.
                 */
    ALG_ID      aiDiversAlgId;
                /*!< Определяет алгоритм диверсификации ключа.
		 * Устанавливается в CALG_PRO_DIVERS, CALG_RIC_DIVERS
		 * или CALG_PRO12_DIVERS.
		 * При указании CALG_PRO_DIVERS диверсификация производится в
		 * соответствии с алгоритмом, описанным в п. 7 RFC 4357.
		 * При указании CALG_PRO12_DIVERS диверсификация производится
		 * в соответствии с алгоритмом, описанным в п. 4.5
		 * Рекомендаций по стандартизации "Использование криптографических
		 * алгоритмов, соответствующих применению стандартов
		 * ГОСТ Р 34.10-2012 И ГОСТ Р 34.11-2012", утвержденных
		 * ТК 26 "Криптографическая защита информации".
                 */
    DWORD       dwDiversMagic;
                /*!< Признак диверсификации ключа,
                 * устанавливается в \ref DIVERS_MAGIC.
                 */
   /*    BYTE        *pbDiversData;
                !< Указатель на данные, по которым диверсифицируется ключ.
                 */
    DWORD       cbDiversData;
                /*!< Длина данных, по которым диверсифицируется ключ.
                 */
} CRYPT_DIVERSBLOBHEADER, *LPCRYPT_DIVERSBLOBHEADER;

/*!
 * \ingroup ProCSPData
 *
 * \brief Структура CRYPT_DIVERSBLOB описывает блоб
 * типа DIVERSBLOB для процедуры диверсификации ключей КриптоПро CSP.
 *
 * \req_wincryptex
 * \sa CRYPT_DIVERSBLOBHEADER
 * \sa CPImportKey
 */
typedef struct _CRYPT_DIVERSBLOB {
    CRYPT_DIVERSBLOBHEADER DiversBlobHeader;
                /*!< Заголовок блоба, диверсифицирующего ключ.
                 */
    BYTE        bDiversData[1/*массив переменной длины: [4..40] байтов*/];
                /*!< Данные, по которым диверсифицируется ключ.
                 */
} CRYPT_DIVERSBLOB, *LPCRYPT_DIVERSBLOB;

/* Определения для структуры CRYPT_KDF_TREE_DIVERSBLOB*/
/*!
 * \ingroup ProCSPData
 *
 * \brief Структура CRYPT_KDF_TREE_DIVERSBLOB_HEADER описывает блоб
 * типа KDF_TREE_DIVERSBLOB для процедуры диверсификации КриптоПро CSP,
 * предусматривающей возможность выработки нескольких ключей.
 * 
 * \req_wincryptex
 * \sa CRYPT_KDF_TREE_DIVERSBLOB
 * \sa CPImportKey
 */
typedef struct _CRYPT_KDF_TREE_DIVERSBLOB_HEADER {
    BLOBHEADER  BlobHeader;
		/*!< Общий заголовок блоба, диверсифицирующего ключ.
		*/
    ALG_ID      aiDiversAlgId;
		/*!< Определяет алгоритм диверсификации ключей.
		* Устанавливается в CALG_KDF_TREE_GOSTR3411_2012_256.
		* Диверсификация производится в соответствии
		* с алгоритмом, описанным в п. 4.5 рекомендаций по
		* стандартизации "Криптографические алгоритмы,
		* сопутствующие применению алгоритмов электронной
		* цифровой подписи и функции хэширования", утвержденных
		* ТК 26 "Криптографическая защита информации".
		*/
    DWORD	dwIterNum;
		/*!< Определяет номер результирующего ключа.
		*/
} CRYPT_KDF_TREE_DIVERSBLOB_HEADER, *LPCRYPT_KDF_TREE_DIVERSBLOB_HEADER;

/*!
 * \ingroup ProCSPData
 *
 * \brief Структура CRYPT_KDF_TREE_DIVERS_INFO содержит параметры
 * R, L, длины Seed и Label для процедуры диверсификации КриптоПро CSP,
 * предусматривающей возможность выработки нескольких ключей.
 *
 * \req_wincryptex
 * \sa CRYPT_KDF_TREE_DIVERSBLOB
 * \sa CPImportKey
 */
typedef struct _CRYPT_KDF_TREE_DIVERS_INFO {
    DWORD       L_value;
                /*!< Значение L для алгоритма диверсификации */
    DWORD       R_value;
                /*!< Значение R для алгоритма диверсификации */
    DWORD       dwSeedLen;
                /*!< Длина значения Seed для алгоритма диверсификации */
    DWORD       dwLabelLen;
                /*!< Длина значения Label для алгоритма диверсификации */
} CRYPT_KDF_TREE_DIVERS_INFO, *LPCRYPT_KDF_TREE_DIVERS_INFO;

/*!
 * \ingroup ProCSPData
 *
 * \brief Структура CRYPT_KDF_TREE_DIVERSBLOB описывает блоб
 * типа KDF_TREE_DIVERSBLOB для процедуры диверсификации КриптоПро CSP,
 * предусматривающей возможность выработки нескольких ключей.
 *
 * \req_wincryptex
 * \sa CRYPT_KDF_TREE_DIVERSBLOB_HEADER
 * \sa CRYPT_KDF_TREE_DIVERS_INFO
 * \sa CPImportKey
 */
typedef struct _CRYPT_KDF_TREE_DIVERSBLOB {
    CRYPT_KDF_TREE_DIVERSBLOB_HEADER KdfTreeBlobHeader;
                /*!< Заголовок блоба, диверсифицирующего ключ.
                *  Содержит общий заголовок блоба, алгоритм диверсификации
                * и номер результирующего ключа.
                */
    CRYPT_KDF_TREE_DIVERS_INFO KdfTreeDiversInfo;
                /*!< Структура, содержащая общую информацию о
                *  диверсификации: параметры R, L, длины Seed и Label.
                */
    BYTE        bDiversData[1/*массив переменной длины*/];
                /*!< Массив длины KdfTreeDiversInfo.dwSeedLen +
				*  KdfTreeDiversInfo.dwLabelLen, содержащий
                *  информацию о диверсификации: значения Seed и Label
                */
} CRYPT_KDF_TREE_DIVERSBLOB, *LPCRYPT_KDF_TREE_DIVERSBLOB;


/*!
* \ingroup ProCSPData
*
* \brief Структура CRYPT_KEYSET_INFO содержит информацию
* о ключе, сохраненном в контейнере.
* key_spec - константа, по которой может быть получен хендл ключа функцией \ref CPGetUserKey.
* alg_id - идентификатор алгоритма ключа.
* \req_wincryptex
* \sa CPGetKeyParam
*/
typedef struct _CRYPT_KEYSET_INFO {
    DWORD key_spec;
    ALG_ID alg_id;
} CRYPT_KEYSET_INFO, *LPCRYPT_KEYSET_INFO;


/*!
* \ingroup ProCSPData
*
* \brief Структура CRYPT_KEYSET_ENUM содержит информацию
* обо всех ключах, сохраненных в контейнере.
* count принимает значение от 0 до 2, в зависимости от числа постоянных ключей в контейнере.
* В массиве описываются присутствующие в контейнере постоянные ключи.
* \req_wincryptex
* \sa CPGetKeyParam
*/
typedef struct _CRYPT_KEYSET_ENUM {
    DWORD count;
    CRYPT_KEYSET_INFO elements[2];
} CRYPT_KEYSET_ENUM, *LPCRYPT_KEYSET_ENUM;

/*!
* \ingroup ProCSPData
*
* \brief Флаг CRYPT_KEYSET_ENUM_FLAG передается в функцию \ref CPGetKeyParam с параметром PP_CONTAINER_STATUS.
* Если получен такой запрос, возвращается структура \ref CRYPT_KEYSET_ENUM, в которой перечислены
* присутствующие в контейнере постоянные ключи. 
* Получение параметра не требует аутентификации.
* \req_wincryptex
* \sa CPGetKeyParam
*/
#define CRYPT_KEYSET_ENUM_FLAG 1


/*!
* \ingroup ProCSPData
*
* \brief Структура CRYPT_KEY_EXHAUSTION_INFO содержит информацию
* о текущих значениях параметров нагрузки на ключ КриптоПро CSP и
* предусматривает их изменение в большую сторону с помощью вызова CPSetKeyParam.
*
* \req_wincryptex
* \sa CPSetKeyParam
*/
typedef struct _CRYPT_KEY_EXHAUSTION_INFO {
    ULONGLONG	 ullAccCipherTextLen;
    ULONGLONG    ullCommAccCipherTextLen;
    ULONGLONG    ullCommCipherTextLenOnBaseKey;
    ULONGLONG    ullNumberOfEncryptionsOnBaseKey;
    ULONGLONG	 ullCommFinal;
} CRYPT_KEY_EXHAUSTION_INFO, *LPCRYPT_KEY_EXHAUSTION_INFO;

/*! \brief Константы, используемые в окне выбора носителя */
/*! \brief Максимальное число аплетов на носителе */
#define CRYPTOAPI_SELECT_READER_MAX_APPLET_COUNT 10
/*! \brief Максимальное число иконок у считывателя */
#define CRYPTOAPI_SELECT_READER_ICONS_NUMBER 5
/*! \brief Максимальное число контекстов считывателей */
#define CRYPTOAPI_SELECT_READER_MAX_CONTEXT_COUNT 3

/*! \brief Хендл считывателя/носителя */
typedef ULONGLONG HSELREADER;
/*! \brief Хендл иконки */
typedef ULONGLONG HSELREADERICON;
/*! \brief Хендл списка считывателей в оконном интерфейсе */
typedef ULONGLONG HSELREADERLISTCONTEXT;
/*! \brief Хендл контекста оконного интерфейса для функции выбора носителя */
typedef ULONGLONG HSELREADERINITDATA;
/*! \brief Хендл контекста оконного интерфейса для функции отображения сообщения*/
typedef ULONGLONG HDISPMESSAGECONTEXT;

/*! \brief Установка параметров оконного интерфейса: начало перечисления считывателей */
#define CRYPT_READER_WND_LIST_FIRST 1
/*! \brief Установка параметров оконного интерфейса: перечисление считывателей */
#define CRYPT_READER_WND_LIST_NEXT  2
/*! \brief Установка параметров оконного интерфейса: закрытие перечисления считывателей */
#define CRYPT_READER_WND_LIST_FREE  3
/*! \brief Установка параметров оконного интерфейса: установка ответа оконной функции */
#define CRYPT_READER_WND_ANSWER	    4
/*! \brief Установка параметров оконного интерфейса: установка считывателя по умолчанию */
#define CRYPT_READER_WND_DEFAULT    5
/*! \brief Установка параметров оконного интерфейса: удаление контекста считывателя */
#define CRYPT_READER_WND_DELETE	    6
/*! \brief Установка параметров оконного интерфейса: получение иконки */
#define CRYPT_READER_WND_ICON	    7

/*!
* \ingroup ProCSPData
*
* \brief Структура для передачи параметров от оконного интерфейса 
*
* \req_wincryptex
* \sa CPSetProvParam
*/
typedef struct {
    DWORD param_type;			/*!< Тип параметра */
    union {
	HSELREADERINITDATA context;		/*!< Для CRYPT_READER_WND_LIST_FIRST - контекст оконного интерфейса */
	HSELREADERLISTCONTEXT list_context;	/*!< Для CRYPT_READER_WND_LIST_NEXT, CRYPT_READER_WND_LIST_FREE - хендл списка */
	struct {
	    HSELREADERINITDATA	    context;	/*!< Контекст оконного интерфейса */
	    HSELREADER		    reader;	/*!< Хендл считывателя */
	    unsigned int	    current_applet; /*!< Номер аплета. Нужен только при CRYPT_READER_WND_ANSWER */
	} reader; /*!< Для CRYPT_READER_WND_ANSWER, CRYPT_READER_WND_DEFAULT, CRYPT_READER_WND_DELETE - информация о считывателе */
	struct {
	    HSELREADERINITDATA	context;    /*!< Контекст оконного интерфейса */
	    HSELREADERICON	hicon;	    /*!< Контекст иконки */
	    DWORD	x_icon;		/*!< Число пикселов в иконке по горизонтали */
	    DWORD	y_icon;         /*!< Число пикселов в иконке по вертикали */
            DWORD       priority;	/*!< максимальный возможный приоритет запрашиваемой иконки */
	} icon; /*!< Для CRYPT_READER_WND_ICON - информация об иконке */
    } info; /*!< Передаваемая информация */
} CRYPT_READER_WND_PARAM;

/*! \brief Тип пароля: пароль или pin. Значение устарело */
#define CRYPT_PIN_PASSWD 0
/*! \brief Тип пароля: имя контейнера зашифрования
     Используется имя контейнера. */
#define CRYPT_PIN_ENCRYPTION 1
/*! \brief Тип пароля: разбивка контейнера на части. Используются имена контейнеров. Описание разделённого контейнера сохраняется на носителе. */
#define CRYPT_PIN_NK 2
/*! \brief Тип пароля: неизвестен */
#define CRYPT_PIN_UNKNOWN 3
/*! \brief Тип пароля: тип и значение выбираются в окне. */
#define CRYPT_PIN_QUERY 4
/*! \brief Тип пароля: Очистить пароль. */
#define CRYPT_PIN_CLEAR 5
/*! \brief Тип пароля: определяется аппаратным модулем. */
#define CRYPT_PIN_HARDWARE_PROTECTION 6
/*! \brief Тип пароля: пароль для FKC контейнера, для аутентификации по EKE */
#define CRYPT_PIN_FKC_EKE 	7
/*! \brief Тип аутентификации: функции для вызова из окна ввода пароля */
#define CRYPT_PIN_WND		8
/*! \brief Тип пароля: разбивка контейнера на части. Имена контейнеров не записываются в информацию о разделённом контейнере. 
 * Разделенный контейнер открывается на виртуальном считывателе.  */
#define CRYPT_PIN_NK_NONAME 9
 /*! \brief Тип пароля: разбивка контейнера на части. Используются имена контейнеров. Разделенный контейнер открывается на виртуальном считывателе. 
  * Используется только для получения информации об аутентификации. Для задания аутентификации не применяется. */
#define CRYPT_PIN_NK_VIRTUAL 10

/*!
 * \ingroup ProCSPData
 *
 * \brief Структура передачи информации из диалога ввода пароля для предъявления или смены пароля
 *
 * \req_wincryptex
 * \sa CPSetProvParam
 */
typedef struct
{
    DWORD auth_type;			/*!< идентификатор той аутентификации, которая устанавливается или меняется */
    DATA_BLOB password;			/*!<  место хранения пароля */
    struct
    {
	unsigned save_in_cache : 1;	/*!<  1, если пароль нужно сохранить в глобальном кэше*/
	unsigned save_in_system : 1;	/*!<  1, если требуется сохранить пароль в реестре */
    } flags;
    DATA_BLOB   reserved;		    /*!<  здесь передается вторая аутентификация */
} CRYPT_PIN_WND_SOURCE_PARAM;

#define CRYPT_PIN_WND_PARAM_CLEAR   0 /*!< Тип передаваемой информации.  Очистка установленнного ранее указателя на служебную информацию. */
#define CRYPT_PIN_WND_PARAM_INFO    1 /*!< Тип передаваемой информации.  Передается указатель на служебную информацию, переданную диалогу ввода пароля, для установки в качестве параметров контекста криптопровайдера. */
#define CRYPT_PIN_WND_PARAM_AUTH    2 /*!< Тип передаваемой информации.  Передается информация об аутентификации. */
#define CRYPT_PIN_WND_PARAM_BOTH    (CRYPT_PIN_WND_PARAM_INFO | CRYPT_PIN_WND_PARAM_AUTH )/*!< Тип передаваемой информации.  Передается указатель на служебную информацию, переданную диалогу ввода пароля и информация об аутентификации. Установка переданного указателя 
				       *   в качестве параметров контекста криптопровайдера не производится. */

/*!
* \ingroup ProCSPData
*
* \brief Структура передачи информации из диалога ввода пароля
*
* \req_wincryptex
* \sa CPSetProvParam
*/
typedef struct
{
    BYTE info_type;  /*!< Тип передаваемой информации. Может быть равен CRYPT_PIN_WND_PARAM_CLEAR, CRYPT_PIN_WND_PARAM_INFO, CRYPT_PIN_WND_PARAM_AUTH, CRYPT_PIN_WND_PARAM_BOTH */
    void * info;			    /*!<  Поле для передачи указателя на служебную информацию. */
    CRYPT_PIN_WND_SOURCE_PARAM auth;	    /*!< Поле для описания аутентификаций. */
} CRYPT_PIN_WND_PARAM;

/*!
 * \ingroup ProCSPData
 *
 * \brief Структура передачи информации для слияния частей контейнера
 *
 * \req_wincryptex
 * \sa CPSetProvParam
 */
typedef struct _CRYPT_PIN_NK_PARAM {
    short n; /*!< Количество передаваемых частей. */
    short k; /*!< Количество частей для загрузки. */
    DWORD *parts; /*!< 32-битные внутренние идентификаторы частей контейнера. */
} CRYPT_PIN_NK_PARAM;

/*!
 * \brief Структура передачи пароль, pin-кода, имени контейнера,
 *  HANDLE контейнера при смене пароля.
 */
typedef union _CRYPT_PIN_SOURCE {
    char *passwd; /*!< Пароль, PIN-код, имя контейнера. */
    DWORD prov; /*!< 32-битный внутренний идентификатор контейнера. */
    CRYPT_PIN_NK_PARAM nk_handles; /*!< Разбивка на NK по идентификаторам */
    CRYPT_PIN_WND_PARAM wnd;	    /*!< Информация из диалогового окна*/
} CRYPT_PIN_SOURCE;

/*!
 * \ingroup ProCSPData
 *
 * \brief Структура передачи информации для:
 *  1) смены пароля контейнера,
 *  2) указания способа доступа к контейнеру (имя, handle, пароль), на ключе которого
 *     зашифровано содержимое другого контейнера.
 *
 * \req_wincryptex
 * \sa CPSetProvParam
 */
typedef struct _CRYPT_PIN_PARAM {
    BYTE type;
    /*!< Тип данных.
 *  CRYPT_PIN_PASSWD - пароль или PIN,
 *  CRYPT_PIN_ENCRYPTION - HANDLE контейнера зашифрования.
 *  CRYPT_PIN_QUERY - тип и значение выбираются в окне,
 *  CRYPT_PIN_CLEAR - очистить пароль.
 *  CRYPT_PIN_NK - разбить на части k из n.
 *  CRYPT_PIN_WND - информация из диалогового окна ввода пароля.
 */
     CRYPT_PIN_SOURCE dest; /*!< Данные соответствующего типа */
} CRYPT_PIN_PARAM;


/*!
 * \ingroup ProCSPData
 *
 * \brief Длина идентификатора разбиения виртуальнгого контейнера
 *
 * \req_wincryptex
 * \sa CPGetProvParam, CRYPT_NK_INFO_PARAM, CRYPT_PIN_INFO
 */
#define CRYPT_NK_IDENTIFIER_LEN 8

 /*!
  * \ingroup ProCSPData
  *
  * \brief Флаг, указывающий, что во флагах CPSetProvParam передается индекс части.
  *
  * \req_wincryptex
  * \sa CPSetProvParam, PP_NK_SYNC
  */
#define CRYPT_NK_PART_INDEX 0x100000


/*!
 * \ingroup ProCSPData
 *
 * \brief Структура получения информации о контейнере разделенного на части.
 *
 * \req_wincryptex
 * \sa CPGetProvParam
 */
typedef struct _CRYPT_NK_INFO_PARAM {
    short n; /*!< Количество частей, на которые разделен контейнер. */
    short k; /*!< Количество частей, достаточных для получения колюча. */
    char parts[1]; /*!< Последовательность n ASCIIZ строк. */
} CRYPT_NK_INFO_PARAM;

/*!
 * \ingroup ProCSPData
 *
 * \brief Структура для получения информации о пароле на контейнер.
 *
 * \req_wincryptex
 * \sa CPGetProvParam
 */
typedef struct _CRYPT_PASSWD_INFO_PARAM {
    unsigned min_passwd_length; /*!< Минимальный допустимый размер пароля. */
    unsigned max_passwd_length; /*!< Максимальный допустимый размер пароля. */
    unsigned passwd_type; /*!< Тип пароля. */
} CRYPT_PASSWD_INFO_PARAM;

#define CSP_INFO_SIZE sizeof(CSP_INFO)

/*!
* \ingroup ProCSPData
*
* \brief Структура для получения информации о пароле на контейнер.
*
* \req_wincryptex
* \sa CPGetProvParam, CRYPT_PASSWD_INFO_PARAM, CRYPT_NK_INFO_PARAM
*/
typedef union _CRYPT_PIN_INFO_SOURCE {
    CRYPT_PASSWD_INFO_PARAM passwd;
    CRYPT_NK_INFO_PARAM nk_info;
    char encryption[1];
} CRYPT_PIN_INFO_SOURCE;

/*!
* \ingroup ProCSPData
*
* \brief Структура для получения информации о пароле на контейнер.
*
* \req_wincryptex
* \sa CPGetProvParam, CRYPT_PIN_INFO_SOURCE
*/
typedef struct _CRYPT_PIN_INFO {
    BYTE type; /*!< Тип данных.
 *  CRYPT_PIN_UNKNOWN - тип неизвестен
 *  CRYPT_PIN_PASSWD - пароль или PIN,
 *  CRYPT_PIN_ENCRYPTION - HANDLE контейнера зашифрования.
 *  CRYPT_PIN_NK - получение N, K, имен частей. На эфемерном считывателе в конец массива имен дописывает идентификатор разбиения.
 *  CRYPT_PIN_HARDWARE_PROTECTION - тип защиты определяется аппаратным модулем
 *  CRYPT_PIN_CLEAR - пароль для аутентентификации не требуется либо установлен по умолчанию
 *  CRYPT_PIN_NK_NONAME - получение N, K, идентификатор разбиения в поле parts.
 */
     CRYPT_PIN_INFO_SOURCE dest; /*!< Данные соответствующего типа */
} CRYPT_PIN_INFO;

#define PROVIDER_TYPE_FKC_MAGISTRA 1


/*!
 * \ingroup ProCSPData
 *
 * \brief Структура получения информации о пароле контейнера для аутентификации по EKE
 *
 * \req_wincryptex
 * \sa CPSetProvParam
 */
typedef struct _CRYPT_FKC_EKE_AUTH_INFO_PARAM {
    unsigned min_passwd_length; /*!< Минимальный допустимый размер пароля. */
    unsigned max_passwd_length; /*!< Максимальный допустимый размер пароля. */
    unsigned count_eke; /*!< Счетчик оставшихся операций EKE. */
    unsigned count_dh; /*!< Счетчик оставшихся операций Диффи-Хеллмана. */
    unsigned count_sig; /*!< Счетчик оставшихся операций подписи. */
    unsigned count_err; /*!< Счетчик оставшихся ошибок. */
    unsigned count_cerr; /*!< Счетчик оставшихся последовательных ошибок. */
    char fname[1]; /*!< UTF8Z-строка дружественного имени. */
} CRYPT_FKC_EKE_AUTH_INFO_PARAM;

#define CPCAR_COUNTER_TRYES 0	/*!< индекс счетчика оставшихся попыток в массиве счетчиков*/
#define CPCAR_COUNTER_CSP_REM 1 /*!< индекс счетчика оставшихся ошибочных операций CSP*/
#define CPCAR_COUNTER_CAR_REM_ERR 2 /*!< индекс счетчика оставшихся ошибочных операций носителя*/
#define CPCAR_COUNTER_CAR_REM_CERR 3 /*!< индекс счетчика оставшихся ошибочных операций носителя подряд*/
#define CPCAR_COUNTER_CAR_REM_AUTH 4 /*!< индекс счетчика оставшихся аутентификаций на носителе*/

#define CPCAR_COUNTER_ROOT_NUMBER 5 /*!<  максимальное число счетчиков для административной аутентификации */

#define CPCAR_COUNTER_CAR_REM_DH 5 /*!<  индекс счетчика оставшихся операций ДХ в контейнере */
#define CPCAR_COUNTER_CAR_REM_SIGN 6 /*!<  индекс счетчика оставшихся операций подписи в контейнере */
#define CPCAR_COUNTER_CAR_SIGN 7 /*!<  индекс счетчика выполненных операций подписи в контейнере */

#define CPCAR_COUNTER_CONTAINER_NUMBER 8 /* максимальное число счетчиков контейнера */

/*!
* \ingroup ProCSPData
*
* \brief структура для получения счетчиков аутентификаций.
*
* \req_wincryptex
* \sa CPGetProvParam, CRYPT_FKC_PIN_INFO, CRYPT_FKC_PIN_INFO_SOURCE
*/
typedef struct
{
    DWORD main_counters[CPCAR_COUNTER_CONTAINER_NUMBER];  /*!< счетчики для основной аутентификации */
    DWORD unblocking_counters[CPCAR_COUNTER_ROOT_NUMBER];	/*!< счетчики для аутентификации изменения аутентификации */
    DWORD error;					/*!< ошибка, требующая отображения в сообщении пользователя. Например "исчерпаны попытки ввода" */
} CRYPT_WND_INFO_PARAM;

/*!
* \ingroup ProCSPData
*
* \brief Структура для получения информации о пароле на контейнер.
*
* \req_wincryptex
* \sa CPGetProvParam, CRYPT_PIN_INFO_SOURCE, CRYPT_FKC_EKE_AUTH_INFO_PARAM
*/
typedef union _CRYPT_FKC_PIN_INFO_SOURCE 
{
    CRYPT_PIN_INFO_SOURCE passwd; /*!< обычный пароль. */
    CRYPT_FKC_EKE_AUTH_INFO_PARAM eke_passwd; /*!< пароль по EKE. */
    CRYPT_WND_INFO_PARAM wnd_info; /*!< счетчика для окна. */
} CRYPT_FKC_PIN_INFO_SOURCE;

/*!
* \ingroup ProCSPData
*
* \brief Структура для получения информации о пароле на контейнер.
*
* \req_wincryptex
* \sa CPGetProvParam, CRYPT_FKC_PIN_INFO_SOURCE
*/
typedef struct _CRYPT_FKC_PIN_INFO {
    BYTE type;
    /*!< Тип данных.
     *  CRYPT_PIN_FKC_EKE - пароль передается FKC контейнеру по EKE.
     *  Другие типы как в CSP.
     */
     CRYPT_FKC_PIN_INFO_SOURCE dest; /*!< Данные соответствующего типа */
} CRYPT_FKC_PIN_INFO;


/*! \brief Действие: предъявление пароля */
#define CRYPT_AUTH_PASSWD 0xf0
/*! \brief Действие: предъявление пароля с запросом через пользовательский интерфейс */
#define CRYPT_AUTH_QUERY 0xf1
/*! \brief Действие: удалить аутентификационную информацию данного типа из кэша аутентификаций */
#define CRYPT_AUTH_CLEAR 0xf2
/*! \brief Действие: Очистить число ошибок аутентификации для данной аутентификации */
#define CRYPT_AUTH_RESET_TRIES 0xf3
/*! \brief Действие: Установить паролю администратора значение по умолчанию */
#define CRYPT_AUTH_RESET_ADMIN 0xf4

/*! \brief Тип парольной аутентификации: PUK. Разрешает смену других аутентификаций носителя.*/
#define CRYPT_AUTH_TYPE_PUK 1
/*! \brief Тип парольной аутентификации: ADMIN. Разрешает запись в корень носителя, например, может разрешать создание контейнера. 
           Может быть единственной аутентификацией на носителе, и разрешать доступ на изменение любого контейнера. */
#define CRYPT_AUTH_TYPE_ADMIN 2
/*! \brief Тип парольной аутентификации: CONT. Разрешает изменение контейнера. Действует только для одного контейнера. */
#define CRYPT_AUTH_TYPE_CONT 3
/*! \brief Тип парольной аутентификации: USER1. Дополнительная аутентификация, по принципу действия предполагается аналогичной ADMIN. Не используется. */
#define CRYPT_AUTH_TYPE_USER_PIN1 4
/*! \brief Тип парольной аутентификации: USER2. Дополнительная аутентификация, по принципу действия предполагается аналогичной ADMIN. Не используется. */
#define CRYPT_AUTH_TYPE_USER_PIN2 5

/*! \brief Алгоритм парольной аутентификации: NO. Означает, что физический носитель не требует аутентификации, и ее реализация лежит на криптопровайдере. */
#define CRYPT_AUTH_ALG_NO 0
/*! \brief Алгоритм парольной аутентификации: SELF. Означает, что аутентификация выполняется носителем по запросу криптопровайдера средствами носителя или считывателя (например, аутентификация по пину на пин-паде). */
#define CRYPT_AUTH_ALG_SELF 1
/*! \brief Алгоритм парольной аутентификации: SIMPLE. Прямое предъявление пин-кода носителю. */
#define CRYPT_AUTH_ALG_SIMPLE 2
/*! \brief Алгоритм парольной аутентификации: SESPAKE. Предъявление пароля по алгоритму SESPAKE и установка защищенного соединения с носителем. */
#define CRYPT_AUTH_ALG_SESPAKE 3

/*!
* \ingroup ProCSPData
*
* \brief Структура для получения информации об аутентификации.
*
* \req_wincryptex
* \sa CPGetProvParam, CRYPT_AUTH_INFO
*/
typedef struct {
    BYTE auth_type; /*! \brief Тип аутентификации по месту предъявления (CRYPT_AUTH_TYPE_PUK, CRYPT_AUTH_TYPE_CONT, ...) */
    BYTE auth_alg;  /*! \brief Алгоритм аутентификации (CRYPT_AUTH_ALG_SELF, CRYPT_AUTH_ALG_SIMPLE, ...) */
    DWORD min_length; /*! \brief Минимальная длина пароля */
    DWORD max_length; /*! \brief Максимальная длина пароля */
} CRYPT_AUTH_INFO_AUTH;

#define CRYPT_AUTH_INFO_DEF_ADMIN 1 /* \brief Флаг: В аутентификации администратора установлен пароль по умолчанию. 1 - есть, 0 - нет. */
#define CRYPT_AUTH_INFO_ADMIN_IS_CONT 2 /* \brief Флаг: контейнеры на носителе защищены аутентификацией носителя (ADMIN). 2 - да, 0 - нет. */
#define CRYPT_AUTH_INFO_ADMIN_IS_PUK 4 /* \brief Флаг: одна аутентификация и на изменение аутентификационных данных, и на создание или удаление контейнеров (ADMIN). 4 - да, 0 - нет. */
#define CRYPT_AUTH_INFO_RESETS_COUNTERS 8 /* \brief Флаг: Предъявление аутентификации смены аут.данных автоматически сбрасывает счетчики ошибок в других аутентификациях. 8 - да, 0 - нет. */
#define CRYPT_AUTH_INFO_CAN_RESET_COUNTERS 16 /* \brief Флаг: После предъявления аутентификации смены аут.данных можно сбросить счетчик ошибок в других аутентификациях. 16 - да, 0 - нет. */
#define CRYPT_AUTH_INFO_CAN_CHANGE_AUTH 32 /* \brief Флаг: После предъявления аутентификации смены аут.данных можно изменить аут.данные произвольной аутентификации. 32 - да, 0 - нет. */
#define CRYPT_AUTH_INFO_CAN_RESET_ADMIN 64 /* \brief Флаг: Аутентификации администратора может быть установлен пароль по умолчанию. 64 - да, 0 - нет. */
#define CRYPT_AUTH_INFO_RESTORE_CONT_AFTER_FOLDER_OPEN 128 /* \brief Флаг: После открытия папки контейнера требуется повторное предъявление аутентификации. 128 - да, 0 - нет. */
#define CRYPT_AUTH_INFO_HARDWARE_RESET_ROOT_DEF 256 /* \brief Флаг: Для сброса аутентификации администратора требуется выполнить аппаратное действие. 256 - да, 0 - нет. */
#define CRYPT_AUTH_INFO_CHANGE_WITH_VERIFY 512 /* \brief Флаг: Для изменения аутентификации необходимо предъявление проверочной аутентификации в той же команде. 512 - да, 0 - нет. */
#define CRYPT_AUTH_INFO_COMMON_AUTH 1024 /* \brief Флаг: Аутентификация администратора является общей для этого и других апплетов на данном носителе. 1024 - да, 0 - нет. */
#define CRYPT_AUTH_INFO_MAIN_CAN_NOT_CHANGE_ITSELF 2048 /* \brief Флаг: Под основной аутентификацией нельзя сменить ее пароль. 2048 - нельзя, 0 - можно. */

/*!
* \ingroup ProCSPData
*
* \brief Структура для получения информации об аутентификациях в контексте.
*
* \req_wincryptex
* \sa CPGetProvParam, PP_AUTH_INFO
*/
typedef struct {
    DWORD auth_count; /* \brief Число аутентификаций в контексте. */
    DWORD flags;    /* \brief Флаги набора аутентификаций. Могут быть установлены CRYPT_AUTH_INFO_DEF_ADMIN, CRYPT_AUTH_INFO_ADMIN_IS_CONT, CRYPT_AUTH_INFO_ADMIN_IS_PUK */
    CRYPT_AUTH_INFO_AUTH auth[1]; /* \brief Массив аутентификаций размера auth_count. */
} CRYPT_AUTH_INFO;


#define CRYPT_MAX_PIN_LENGTH 160

typedef struct {
    BYTE action;    /*! Предполагаемое действие: CRYPT_AUTH_PASSWD, CRYPT_AUTH_QUERY, CRYPT_AUTH_CLEAR, CRYPT_AUTH_RESET_TRIES. */
    BYTE changed_auth_type; /*! Тип изменяемой аутентификации */
    CHAR changed_pin[CRYPT_MAX_PIN_LENGTH + 1]; /*! Пароль изменяемой аутентификации, если надо, LPSTR */
    BYTE verify_auth_type; /*! \brief Тип предъявляемой аутентификации */
    CHAR verify_pin[CRYPT_MAX_PIN_LENGTH + 1]; /*! \brief Значение пароля предъявляемой аутентификации, LPSTR */
} CRYPT_CHANGE_AUTH;

typedef struct
{
    void * hCSP;	/* ссылка на CSP, в котором осуществляются вызовы */
    void * info;	/* дополнительная информация об устанавливаемых параметрах */
} PWDFKC_CONTEXT;

/*!
 * \ingroup ProCSPData
 *
 * \brief Значения параметра "проверка открытого ключа в операции Диффи-Хеллмана".
 * При установке параметра передается переменной типа DWORD. 
 *
 * \req_wincryptex
 * \sa CPGetProvParam
 * \sa CPSetProvParam
 * \sa CRYPT_FKC_DH_CHECK
 */
typedef enum _CRYPT_FKC_DH_CHECK_VAL
{
    dh_check_disable = 1, /*!< Проверка открытого ключа не осуществляется */
    dh_check_enable = 2 /*!< Проверка открытого ключа осуществляется */
} CRYPT_FKC_DH_CHECK_VAL;

/*!
 * \ingroup ProCSPData
 *
 * \brief Структура для получения статуса проверки открытого ключа.
 * Получает и устанавливает параметр "проверка открытого ключа в операции Диффи-Хеллмана"
 * для провайдеров FKC ( PP_FKC_DH_CHECK ). 
 *
 * \req_wincryptex
 * \sa CPGetProvParam
 * \sa CPSetProvParam
 * \sa CRYPT_FKC_DH_CHECK_VAL
 */
typedef struct _CRYPT_FKC_DH_CHECK
{
    CRYPT_FKC_DH_CHECK_VAL checkdh; /* значение параметра */
    BOOL is_writable; /*!< можно ли установить параметру новое значение */
} CRYPT_FKC_DH_CHECK;

/*!
 * \ingroup ProCSPData
 *
 * \brief Структура для получения и установки настроек кэширования контейнеров.
 *
 * \req_wincryptex
 * \sa CPGetProvParam
 * \sa CPSetProvParam
 */
typedef struct _CRYPT_CACHE_SIZE {
    DWORD cache_size; /*!< Размер кэша. */
    DWORD max_cache_size; /*!< Максимальный размер кэша. */
    BOOL is_writable; /*!< см. CACHE_RO  */
} CRYPT_CACHE_SIZE;

/*!
* \ingroup ProCSPData
*
* \brief Структура для получения и установки различных открытых параметров ключевого контейнера.
* Параметры TContainerParamType_AuthServer, TContainerParamType_SignServer, TContainerParamType_OAuth2_AuthToken и TContainerParamType_OAuth2_IdToken 
* передаются в виде нуль-терминированных ASCII-строк. TContainerParamType_CertificateID в виде DWORD.
* \req_wincryptex
* \sa CPGetProvParam
* \sa CPSetProvParam
*/
typedef enum _TContainerParamType {
    TContainerParamType_Header,
    TContainerParamType_AuthServer,
    TContainerParamType_SignServer, 
    TContainerParamType_OAuth2_AuthToken, 
    TContainerParamType_OAuth2_IdToken, 
    TContainerParamType_Username,
    TContainerParamType_Password,
    TContainerParamType_Certificate,
    TContainerParamType_CertificateID,
    TContainerParamType_Extensions,
    TContainerParamType_Permissions
} TContainerParamType;

typedef struct _CRYPT_CONTAINER_PARAM {
    TContainerParamType param_type;
    DWORD cbData;
    BYTE pbData[1];
} CRYPT_CONTAINER_PARAM;

/*!
* \ingroup ProCSPData
*
* \brief Структура для получения и установки настроек поддержки разных типов носителей.
*
* \req_wincryptex
* \sa CPGetProvParam
* \sa CPSetProvParam
*/

typedef struct _CRYPT_CARRIER_TYPES {
    DWORD enabled_types; /*!< Разрешенные виды носителей. */
    DWORD enabled_operations; /*!< Разрешенные операции для запрещенных носителей. */
} CRYPT_CARRIER_TYPES;

/*!
* \ingroup ProCSPData
*
* \defgroup CarrierTypeFlags Флаги, используемые в параметрах PP_CARRIER_TYPES.
*
* \req_wincryptex
* \sa CPGetProvParam
* \sa CPSetProvParam
*
* \{
*/

/*!
 *  \brief Разрешить использование носителей обычных пассивных криптоконтейнеров (CSP 3.6 - CSP 4.0).
 */
#define ENABLE_CARRIER_TYPE_CSP 0x01

/*!
 *  \brief Разрешить использование ФКН без SM (Рутокен ЭЦП, JaCarta ГОСТ и т.п.).
 */
#define ENABLE_CARRIER_TYPE_FKC_NO_SM 0x02

/*!
 *  \brief Разрешить использование ФКН с SM (SESPAKE).
 */
#define ENABLE_CARRIER_TYPE_FKC_SM 0x04

/*!
 *  \brief Разрешить использование всех видов носителей.
 */
#define ENABLE_ANY_CARRIER_TYPE (ENABLE_CARRIER_TYPE_CSP|ENABLE_CARRIER_TYPE_FKC_NO_SM|ENABLE_CARRIER_TYPE_FKC_SM)

/*!
 *  \brief На запрещенных видах носителей не разрешать никаких операций
 */
#define DISABLE_EVERY_CARRIER_OPERATION 0x00

/*!
 *  \brief На запрещенных видах носителей разрешить только открытие и перечисление контейнеров.
 */
#define ENABLE_CARRIER_OPEN_ENUM 0x01

/*!
 *  \brief На запрещенных видах носителей разрешить только создание контейнеров.
 */
#define ENABLE_CARRIER_CREATE 0x02

/*!
 *  \brief На запрещенных видах носителей разрешить все операции.
 */
#define ENABLE_ANY_OPERATION (ENABLE_CARRIER_OPEN_ENUM|ENABLE_CARRIER_CREATE)

/*! \} */

/*!
* \ingroup ProCSPData
*
* \defgroup CarrierFlags Флаги, возвращаемые через CryptGetProvParam(PP_ENUMREADERS, CRYPT_MEDIA) и CryptGetProvParam(PP_CARRIER_FLAGS)
*
* \req_wincryptex
* \sa CPGetProvParam
*
* \{
*/

/*!
 *  \brief Признак отчуждаемости носителя (установлен у смарт-карт и флеш-накопителей)
 */
#define CARRIER_FLAG_REMOVABLE 1

/*!
 *  \brief Признак наличия уникального номера (установлен у смарт-карт и флеш-накопителей)
 */
#define CARRIER_FLAG_UNIQUE 2
/*!
 *  \brief Признак носителя, защищенного шифрованием на другом контейнере (установлен у HSM)
 */
#define CARRIER_FLAG_PROTECTED 4

/*!
 *  \brief Признак ФКН-носителя (носителя с неизвлекаемыми ключами)
 */
#define CARRIER_FLAG_FUNCTIONAL_CARRIER 8

/*!
 *  \brief Признак ФКН-носителя с поддержкой защищенного обмена сообщениями и протокола SESPAKE
 */
#define CARRIER_FLAG_SECURE_MESSAGING 16

/*!
 *  \brief Признак возможности установки закрытого ключа на ФКН-носитель
 */
#define CARRIER_FLAG_ABLE_SET_KEY 32

/*!
 *  \brief Признак возможности считывателя запрашивать подтверждение подписи (SafeTouch, Рутокен ПинПад)
 */
#define CARRIER_FLAG_ABLE_VISUALISE_SIGNATURE 64

/*!
 *  \brief Признак виртуального считывателя (для разделения и сборки ключей)
 */
#define CARRIER_FLAG_VIRTUAL 128

/*! \} */

/*!
* \ingroup ProCSPData
*
* \brief Блоб с информацией о считывателе, представляющий собой
* сериализованную псевдоструктуру.
*
* \req_wincryptex
* \sa CPGetProvParam
*/
typedef struct _CRYPT_ENUMREADER_INFO {
    char    szNickName[1]; /*!< NickName считывателя - NULL-терминированная строка. */
    char    szName[1]; /*!< Имя считывателя - NULL-терминированная строка. */
    BYTE   Flags; /*!< Флаги считывателя. */
} CRYPT_ENUMREADER_INFO;

/*!
* \ingroup ProCSPData
*
* \brief Блоб с информацией о режиме работы / апплете, представляющий собой
* сериализованную псевдоструктуру.
*
* \req_wincryptex
* \sa CPGetProvParam
*/
typedef struct _CRYPT_ENUMREADER_INFO_MEDIA {
    char    szNickName[1]; /*!< NickName считывателя - NULL-терминированная строка. */
    char    szName[1]; /*!< Имя считывателя - NULL-терминированная строка. */
    char    szMedia[1]; 
    	/*!< NULL-терминированная cтрока с UNIQUE-именем носителя или статусом, если UNIQUE не удалось получить:
         * <table><tr><th>\b szMedia</th><th>Описание</th></tr>
         * <tr><td>
         * NO_MEDIA
         * </td><td>
         *      Карта не вставлена в считыватель или носитель не поддерживается.
         * </td></tr><tr><td>
         * NO_UNIQUE
         * </td><td>
         *      Носитель не поддерживает UNIQUE.
         * </td></tr><tr><td>
         * INVALID_MEDIA
         * </td><td>
         *      При работе с носителем возникли ошибки. С CSP 5.0 не возвращается.
         * </td></tr><tr><td>
         * IS_FKC
         * </td><td>
         *      ФКН-носитель в не-ФКН-провайдере. С CSP 5.0 не возвращается.
         * </td></tr><tr><td>
         * NO_FKC
         * </td><td>
         *      Не-ФКН-носитель в ФКН-провайдере. С CSP 5.0 не возвращается.
         * </td></tr><tr><td>
         * GEM_35000030CFE53C70
         * </td><td>
         *      Пример UNIQUE-имени
         * </td></tr><tr><td>
         * rutoken_2a7d64bb
         * </td><td>
         *      Пример UNIQUE-имени
         * </td></tr><tr><td>
         * JACARTA_0b52002140489243
         * </td><td>
         *      Пример UNIQUE-имени
         * </td></tr><tr><td>
         * ESMART_50CF20508942
         * </td><td>
         *      Пример UNIQUE-имени
         * </td></tr><tr><td>
         * 1082C025
         * </td><td>
         *      Пример UNIQUE-имени
         * </td></tr></table>
    	 */
    BYTE   Flags; /*!< Флаги считывателя. \sa CarrierFlags */
} CRYPT_ENUMREADER_INFO_MEDIA;

/*!
* \ingroup ProCSPData
*
* \brief Блоб с информацией о ДСЧ, представляющий собой
* сериализованную псевдоструктуру.
*
* \req_wincryptex
* \sa CPGetProvParam
*/
typedef struct _CRYPT_ENUMRANDOMS_INFO {
    char    szNickName[1]; /*!< NickName ДСЧ - NULL-терминированная строка. */
    char    szName[1]; /*!< Имя ДСЧ - NULL-терминированная строка. */
    BYTE    Flags; /*!< Флаги ДСЧ. Нулевой бит - признак работоспособности, устанавливаемый при перечислении с CRYPT_AVAILABLE. */
    DWORD   level; /*!< Приоритетный уровень ДСЧ. */
} CRYPT_ENUMRANDOMS_INFO;

/*!
 * \ingroup ProCSPData
 *
 * \brief Структура передачи информации для получения и установки разделённого значения параметра R для ЭЦП 
 *  на базе функционального ключевого носителя.
 *
 * \sa CPGetHashParam
 * \sa CPSetHashParam
 */
typedef struct _CRYPT_HASH_BLOB_EX {
    CRYPT_PUBKEY_INFO_HEADER tPublicKeyParam;
    BYTE    pbData [2*SECRET_KEY_LEN];
} CRYPT_HASH_BLOB_EX, *PCRYPT_HASH_BLOB_EX;

/*!
 * \ingroup ProCSPData
 *
 * \brief Структура для задания периодов действия ключей во вновь создаваемом контейнере
 *
 * \sa CPGetProvParam
 * \sa CPSetProvParam
 */
typedef struct _CRYPT_KEY_PERIOD {
    LONG privateKeySeconds;		/*!< Период действия закрытого ключа, в секундах. */
    LONG publicKeySeconds;		/*!< Период действия открытого ключа, в секундах. */
} CRYPT_KEY_PERIOD, *PCRYPT_KEY_PERIOD;

#define CSP_INFO_FREE_SPACE	(0)	/* свободное место на /var в bytes */
#define CSP_INFO_NUMBER_UL	(1)	/* "\\local\\number_UL" --- количество выпущенных ключей УЛ */
#define CSP_INFO_NUMBER_SIGNS	(2)     /* "\\local\\number_signs" --- количество операций подписи */
#define CSP_INFO_KCARDS_CHANGES	(3)     /* "\\local\\Kcard_changes" --- количество смен карт канала "К" */
#define CSP_INFO_NUMBER_KCARDS	(4)     /* "\\local\\number_Kcard_sessions" --- количество выпущенных в последний раз карт канала "К" */
#define CSP_INFO_NUMBER_KEYS	(5)     /* "\\local\\number_keys" --- количество выпущенных  */
#define CSP_INFO_FUTURE_SIZE	(10)
typedef struct
{
  WORD version;		/* версия структуры */
  DWORD time;		/* time_t */
  DWORD keys_remaining;	/* остаток ДСРФ */
  DWORD future[CSP_INFO_FUTURE_SIZE];
} CSP_INFO;

typedef struct DSS_AUDIT_INFO_
{
    FILETIME time;
    DWORD cbHash;
    BYTE pbHash[64];
} DSS_AUDIT_INFO, *PDSS_AUDIT_INFO;

#define CSP_MODE_LIBRARY	(0)
#define CSP_MODE_SERVICE	(1)
#define CSP_MODE_DRIVER		(2)

/* Длина секретного ключа для ГОСТ 28147, подписи и обмена.*/

#define CPC_FAST_CODE_DEFAULT	0
#define CPC_FAST_CODE_NO	1
#define CPC_FAST_CODE_USER	2

#ifdef UNIX
    #if defined(__GNUC__) && !defined(__arm64__) && !defined(IOS) && (!defined (PROCESSOR_TYPE) || (PROCESSOR_TYPE == PROC_TYPE_I386))
	#define CPCAPI	__attribute__((regparm(0)))
    #else // __GNUC__
	#define CPCAPI
    #endif // __GNUC__
    #define CPC_SIZE_T	SIZE_T
#else // UNIX
    #define CPCAPI	__cdecl
    #define CPC_SIZE_T	size_t
#endif // UNIX

/*!
 * \ingroup ProCSPData
 * \brief Описание функции захвата FPU в режиме ядра ОС.
 *
 *  Функция должна обеспечивать захват FPU (сохраняя
 *  значения регистров MMX (ST) и XMM ). Ей передаются
 *  буфер для сохранения регистров, его размер,
 *  тип функции, использующей дополнительные регистры,
 *  осуществляющей её вызов, и дополнительные параметры,
 *  по которым можно судить о целесообразности захвата.
 *
 * \param buf [in] Невыровненный буфер, предоставляемый провайдером для сохранения
 *  дополнительных регистров.
 *
 * \param sz [in] Размер буфера, переданного провайдером для сохранения
 *  дополнительных регистров.
 *
 * \param bl_len [in] Размер данных, обрабатываемых функцией, запросившей
 * сохранение регистров.
 *
 * \param op_type [in] Тип функции, запросившей сохранение регистров.
 * Тип может быть одним из четырёх:<br>
 * <table><tr><th>
 * Значение \e op_type
 * </th><th>
 *      Тип функции
 * </th></tr><tr><td>
 * #CSP_OPERATION_CIPHER1
 * </td><td>
 *      Нераспараллеливаемые функции шифрования по ГОСТ 28147-89 и ГОСТ Р 34.12–2015 (Магма, Кузнечик).
 * </td></tr><tr><td>
 * #CSP_OPERATION_CIPHER2
 * </td><td>
 *      Распараллеливаемые функции шифрования по ГОСТ 28147-89 и ГОСТ Р 34.12–2015 (Магма, Кузнечик).
 * </td></tr><tr><td>
 * #CSP_OPERATION_IMIT
 * </td><td>
 *      Функции выработки имитовставки по ГОСТ 28147-89 и ГОСТ Р 34.12–2015 (Магма, Кузнечик).
 * </td></tr><tr><td>
 * #CSP_OPERATION_HASH
 * </td><td>
 *      Функции хэширования по ГОСТ Р 34.11-94 и ГОСТ Р 34.11-2012.
 * </td></tr></table>
 *
 * \return результат захвата сопроцессора FPU.
 *
 * \retval TRUE Захват сопроцессора был осуществлён.
 * В этом случае провайдер вызовет функцию, использующую
 * MMX, SSE2, SSSE3 или AVX, и после неё - функцию \ref CPC_Kernel_Fpu_End_Callback .
 * Различные типы функций провайдера работают с разными скоростями,
 * и для целесообразности захвата FPU передаются как тип функции провайдера,
 * так и количество обрабатываемых данных.
 * \retval FALSE Захват не был осуществлён. В этом случае
 * провайдер вызовет функцию, использующую только стандартный набор
 * инструкций (универсальную).
 * \sa CPC_FAST_CODE
 * \sa CPC_Kernel_Fpu_End_Callback
 * \sa CPSetProvParam()
 * \sa CPCSetProvParam()
 */
typedef BOOL CPCAPI CPC_Kernel_Fpu_Begin_Callback(
    /* [in] */ BYTE * buf,
    /* [in] */ CPC_SIZE_T sz,
    /* [in] */DWORD bl_len,
    /* [in] */DWORD op_type);


/*!
 * \ingroup ProCSPData
 * \brief Описание функции освобождения FPU в режиме ядра ОС.
 *
 *  Функция должна обеспечивать освобождение FPU (восстанавливая
 *  значения регистров MMX (ST) и XMM ). Ей передаются буфер
 *  для сохранения регистров, его размер, тип функции, использовавшей
 *  в провайдере дополнительные регистры, и осуществившей вызов парной
 *  функции \ref CPC_Kernel_Fpu_Begin_Callback .
 *
 * \param buf [in] Буфер, предоставляемый провайдером для сохранения
 *  дополнительных регистров. В нем должна была сохранить состояние
 *  сопроцессора функция \ref CPC_Kernel_Fpu_Begin_Callback .
 *
 * \param sz [in] Размер буфера, переданного провайдером для сохранения
 *  дополнительных регистров.
 *
 * \param op_type [in] Тип функции, запросившей сохранение регистров.
 * Тип может быть одним из четырех:<br>
 * <table><tr><th>
 * Значение \e op_type
 * </th><th>
 *      Тип функции
 * </th></tr><tr><td>
 * #CSP_OPERATION_CIPHER1
 * </td><td>
 *      Нераспараллеливаемые функции шифрования по ГОСТ 28147-89 и ГОСТ Р 34.12–2015 (Магма, Кузнечик).
 * </td></tr><tr><td>
 * #CSP_OPERATION_CIPHER2
 * </td><td>
 *      Распараллеливаемые функции шифрования по ГОСТ 28147-89 и ГОСТ Р 34.12–2015 (Магма, Кузнечик).
 * </td></tr><tr><td>
 * #CSP_OPERATION_IMIT
 * </td><td>
 *      Функции выработки имитовставки по ГОСТ 28147-89 и ГОСТ Р 34.12–2015 (Магма, Кузнечик).
 * </td></tr><tr><td>
 * #CSP_OPERATION_HASH
 * </td><td>
 *      Функции хэширования по ГОСТ Р 34.11-94 и ГОСТ Р 34.11-2012.
 * </td></tr></table>
 *
 * \return результат освобождения сопроцессора FPU.
 *
 * \retval TRUE Освобождение сопроцессора было осуществлено.
 * \retval FALSE Освобождение не было осуществлено.
 *
 * \sa CPC_FAST_CODE
 * \sa CPC_Kernel_Fpu_Begin_Callback
 * \sa CPSetProvParam()
 * \sa CPCSetProvParam()
 */
typedef BOOL CPCAPI CPC_Kernel_Fpu_End_Callback(
    /* [in] */ BYTE * buf,
    /* [in] */ CPC_SIZE_T sz,
    /* [in] */ DWORD op_type);

/*!
 *  \ingroup ProCPCData
 *
 *  \brief Настройки использования расширений процессора: MMX, SSE2, SSSE3, AVX, AVX2.
 *
 *  На процессорах ia-32 и amd64 можно достичь ускорения алгоритмов
 *  шифрования и хэширования за счёт использования инструкций расширений
 *  MMX, SSE2, SSSE3, AVX. Настройка захвата FPU осуществляется с помощью
 *  данной структуры.
 *
 *  Криптографические функции, использующие расширения, сведены в
 *  следующие наборы:
 *  <table><tr><th>
 * Идентификатор набора
 * </th><th>
 *      Группа
 * </th></tr><tr><td>
 * #CSP_OPERATION_CIPHER1
 * </td><td>
 *      Нераспараллеливаемые функции шифрования по ГОСТ 28147-89 и ГОСТ Р 34.12–2015 (Магма, Кузнечик).
 *	Для быстрой работы необходимо только командное расширение MMX.
 * </td></tr><tr><td>
 * #CSP_OPERATION_CIPHER2
 * </td><td>
 *      Распараллеливаемые функции шифрования по ГОСТ 28147-89 и ГОСТ Р 34.12–2015 (Магма, Кузнечик).
 *      Быстрая работа возможна в режимах MMX, SSSE3 и AVX.
 * </td></tr><tr><td>
 * #CSP_OPERATION_IMIT
 * </td><td>
 *      Функция выработки имитовставки по ГОСТ 28147-89 и ГОСТ Р 34.12–2015 (Магма, Кузнечик).
 *	Для быстрой работы необходимо только командное расширение MMX.
 * </td></tr><tr><td>
 * #CSP_OPERATION_HASH
 * </td><td>
 *      Функции хэширования по ГОСТ Р 34.11-94 и ГОСТ Р 34.11-2012.
 *	Для них необходимы командные расширения MMX и SSE2.
 * </td></tr><tr><td>
 * #CSP_OPERATION_MULT
 * </td><td>
 *      Функция умножения в поле по модулю P (Применяется в протоколах подписи и Диффи-Хеллмана).
 *	Для быстрой работы необходимы командные расширения MMX и SSE2.
 * </td></tr><tr><td>
 * #CSP_FAST_CODE_DISABLE_SSSE3
 * </td><td>
 *      Запрет использования командного расширения SSSE3.
 * </td></tr><tr><td>
 * #CSP_FAST_CODE_DISABLE_AVX
 * </td><td>
 *      Запрет использования командного расширения AVX и AVX2.
 * </td></tr><tr><td>
 * #CSP_FAST_CODE_DISABLE_AVX2
 * </td><td>
 *      Запрет использования командного расширения AVX2.
 * </td></tr><tr><td>

 * #CSP_FAST_CODE_RT_TS
 * </td><td>
 *      Захват FPU только на время операции, применяется в случае если
 *      для захвата используется TS-бит (Solaris, Linux).
 * </td></tr></table>
 * Совокупность выборов универсальных или использующих командные расширения
 * наборов функций будем называть сочетанием наборов. Любое сочетание наборов
 * кодируется в одном 32-битном значении как логическая сумма
 * идентификаторов наборов функций MMX, SSE2, SSSE3, AVX и AVX2.
 *
 * В связи с большим разнообразием аппаратных платформ на базе процессоров
 * архитектуры x86 и эмуляций x86 на архитектурах x64 и IA64, нет возможности
 * заранее определить, какой из наборов функций в группах будет
 * работать быстрее на конкретном процессоре, с конкретной частотой шины,
 * скоростью памяти и т.п.
 *
 * Настроить провайдер на использование наиболее быстрого сочетания
 * наборов можно:
 * <ol type="1">
 * <li>
 * с помощью вызова SetProvParam (PP_FAST_CODE_FUNCS),
 * в который передаётся данная структура
 * </li>
 * <li>
 * на уровне CPC, при инициализации криптографического модуля, путём передачи
 * данной структуры в инициализатор провайдера
 * </li>
 * <li>
 * при использовании криптопровайдера в пользовательском режиме,
 * путём установки маски оптимального набора функций в реестр в
 * '\\Crypto Pro\\Cryptography\\CurrentVersion\\Parameters\\MMXFuncs'
 * или на Unix командой:
 * "cpconfig -ini '\\config\\Parameters' -add long MMXFuncs значение_маски",
 * куда надо вписать значение соответствующее полю UsedMask из структуры.
 * </li>
 * <li>
 * c помощью команды 'csptest -speed -type ALL -mode REG'.
 * Такой вызов проведёт короткий тест и запишет оптимальные параметры
 * в указанный выше ключ реестра.
 * </li>
 * </ol>
 *
 * У провайдера есть три режима использования функций MMX/SSE2/SSSE3/AVX:
 * <ol type="1">
 * <li>
 *  Некое стандартное сочетание, считающиеся наиболее производительным.
 * </li>
 * <li>
 *  Сочетание, состоящее только из наборов универсальных функций.
 * </li>
 * <li>
 *  Сочетание, устанавливаемое пользователем с помощью функции SetProvParam.
 * </li>
 * </ol>
 *
 * Первое из них при работе через уровни Crypt и CP устанавливаются из реестра,
 * или, если реестр недоступен или параметр не определён, как некоторое
 * стандартное сочетание, задаваемое провайдером для данной системы.
 * При работе на уровне CPC первое сочетание передаётся пользователем
 * при инициализации провайдера, или запрашивается установка
 * стандартного для провайдера сочетания.
 *
 * При установке некоторого выбираемого пользователем сочетания
 * наборов возможен выбор используемого набора расширений:
 * MMX, SSE2, SSSE3, AVX или AVX2.
 * При установке нового сочетания наборов провайдер в любом
 * случае проверит, возможно ли на данном процессоре использование
 * таких наборов функций MMX/SSE2/SSSE3/AVX/AVX2,
 * и, если возможность есть, установит наборы. В режиме ядра, кроме того,
 * перед вызовом каждой функции, использующей MMX/SSE/SSSE3/AVX, будет
 * осуществлён вызов callback'а захвата FPU, и специализированный код
 * будет использоваться только в случае успешного захвата, после
 * чего будет вызван callback функции освобождения FPU.
 * Если захват не удался, будет выполняться универсальный код функции.
 *
 * \note
 * Семантика работы функции CPCSetProvParam (CPC_FAST_CODE) следующая:
 * сначала производится выставление всех наборов функций в медленные
 * (не использующие расширения), а затем - включение
 * быстрых в соответствии с переданными флагами.
 *
 * Пример заполнения структуры для выставления всех наборов функций в медленные с помощью
 * CPCSetProvParam (CPC_FAST_CODE).
 *
 * \code
 * fastCodes.cp_kernel_fpu_begin = NULL;
 * fastCodes.cp_kernel_fpu_end = NULL;
 * fastCodes.Kernel_Buf_Size = 0;
 * fastCodes.UsesFunctions = CPC_FAST_CODE_USER;
 * fastCodes.UsedMask = 0;
 * \endcode
 * 
 * Пример заполнения структуры для включения быстрого кода для всех функций распараллеливаемого шифрования,
 * но с запретом использования AVX. Все наборы функций, кроме
 * CSP_OPERATION_CIPHER2, будут медленными.
 * 
 * \code
 * fastCodes.cp_kernel_fpu_begin = NULL;
 * fastCodes.cp_kernel_fpu_end = NULL;
 * fastCodes.Kernel_Buf_Size = 0;
 * fastCodes.UsesFunctions = CPC_FAST_CODE_USER;
 * fastCodes.UsedMask = CSP_FAST_CODE_DISABLE_AVX | CSP_OPERATION_CIPHER2;
 * \endcode
 * 
 * \note Важно, что бы другие функции определяемые пользователем в
 * конфигурации \ref CPC_CONFIG_ сохраняли возможность
 * использования расширений процессора текущим контекстом
 * исполнения (начиная, со сборки 3.6.7747, определяемые
 * пользователем функции блокировок с ожиданием \ref CPC_LOCK_FUNCS_
 * не вызываются во время использования расширений процессора).
 *
 * \note Поддержка командных расширений по умолчанию на уровне
 * пользователя согласно возможностям процессора и ОС.
 *
 * \note Поддержка командных расширений по умолчанию на уровне ядра ОС:
 *  <table><tr><th>
 * Ядро ОС
 * </th><th>
 *      Поддержка
 * </th></tr><tr><td>
 * Windows 7/2008R2 SP1
 * </td><td>
 *      до AVX
 * </td></tr><tr><td>
 * Windows иные
 * </td><td>
 *      до SSSE3
 * </td></tr><tr><td>
 * Linux с версии ядра 2.6.30
 * </td><td>
 *      до AVX
 * </td></tr><tr><td>
 * Linux ранее
 * </td><td>
 *      до SSSE3
 * </td></tr><tr><td>
 * FreeBSD с версии 8.2
 * </td><td>
 *      до AVX
 * </td></tr><tr><td>
 * FreeBSD ранее
 * </td><td>
 *      базовый код без использования FPU/MMX/SSE2/SSSE3/AVX
 * </td></tr><tr><td>
 * Solaris 10/11 amd64
 * </td><td>
 *      до SSSE3
 * </td></tr><tr><td>
 * Solaris 10/11 ia32
 * </td><td>
 *      базовый код без использования FPU/MMX/SSE2/SSSE3/AVX
 * </td></tr></table>
 *
 * \sa CPC_CONFIG_
 */
typedef struct _CPC_FAST_CODE {
    DWORD UsesFunctions;
		/*!< Обязательный параметр, может быть равен CPC_FAST_CODE_DEFAULT,
		 *   CPC_FAST_CODE_NO, CPC_FAST_CODE_USER.
		 * <table><tr><th>
		 * Возможные значения:</th><th>Интерпретация:
		 * </th>
		 * </tr>
		 * <tr><td>
		 * CPC_FAST_CODE_DEFAULT</td>
		 *	<td>Использовать сочетание наборов по умолчанию.
		 * 	</td></tr>
		 * <tr><td>
		 * CPC_FAST_CODE_NO</td>
		 *	<td>Использовать сочетание наборов универсальных функций.
		 *	</td></tr>
		 * <tr><td>
		 * CPC_FAST_CODE_USER</td>
		 *	<td>Использовать сочетание наборов функций, задаваемое
		 *	параметром UsedMask.
		 *	</td></tr>
		 * </table>
		 */
    CPC_Kernel_Fpu_Begin_Callback * cp_kernel_fpu_begin;
		/*!< Указатель на функцию захвата FPU.
		 *   Применяется в режиме ядра. Указывает на функцию
		 *   захвата FPU, которую будут вызывать функции,
		 *   использующие расширения MMX/SSE2/SSSE3/AVX.
		 *   Устанавливается только при UsesFunctions == CPC_FAST_CODE_USER.
		 *   Если равно нулю при использовании в CPCSetProvParam(),
		 *   сохраняется предыдущее значение.
		 *   См. \ref CPC_Kernel_Fpu_Begin_Callback
		 *
		 */
    CPC_Kernel_Fpu_End_Callback *cp_kernel_fpu_end;
		/*!< Указатель на функцию освобождения FPU.
		 *   Применяется в режиме ядра. Указывает на функцию
		 *   освобождения FPU.
		 *   Используется только при UsesFunctions == CPC_FAST_CODE_USER.
		 *   Если равно нулю при использовании в CPCSetProvParam(),
		 *   сохраняется предыдущее значение.
		 *   См. \ref CPC_Kernel_Fpu_End_Callback
		 */
    DWORD  Kernel_Buf_Size;
		/*!< Размер невыровненного буфера, который будет
		 *   передаваться в функции захвата и освобождения FPU
		 *   для сохранения регистров. Используется
		 *   только при UsesFunctions == CPC_FAST_CODE_USER.
		 *   Значение не может превышать 2048.
		 *   См. \ref CPC_Kernel_Fpu_Begin_Callback ,
		 *   \ref CPC_Kernel_Fpu_End_Callback
		 */
    DWORD   UsedMask;
		/*!< Маска, задающая сочетание наборов функций. Является
		 *   логической суммой идентификаторов наборов функций,
		 *   использующих командные расширения, которые следует
		 *   вызывать в криптопровайдере (см. выше).
		 *   В пользовательском режиме в ней передаются любые
		 *   возможные сочетания всех пяти наборов,
		 *   в режиме ядра - всех, кроме набора умножения по модулю P.
		 */
} CPC_FAST_CODE;

/*! \ingroup ProCSPData
 * \defgroup ProCSPDataFast Переключатели кода
 * Значения переключателей кода на более быстрый (с использованием SSE2).
 *
 * При использовании в функции \ref CPGetProvParam (PP_FAST_CODE_FLAGS), 
 * в параметре pbData возвращаются флаги, определяющие набор 
 * проверенных на включённый код функций.
 * Указание, какие функции проверять на включённый код, передаётся
 * во флагах \e dwFlags.
 *
 * Если применён флаг CRYPT_FAST_CODE_GET_SETFN, при выходе
 * \ref CSP_FAST_CODE_GET_SETFN будет установлен в 1, если провайдер может использовать
 * быстрый код, и 0 - иначе. Если установлен флаг CRYPT_FAST_CODE_ALL_FUNCTIONS,
 * будут проверяться все функции, и на выходе будут установлены все флаги
 * \ref CSP_FAST_CODE_E_ECB, \ref CSP_FAST_CODE_E_CBC, \ref CSP_FAST_CODE_E_CNT,
 * \ref CSP_FAST_CODE_E_CFB, \ref CSP_FAST_CODE_E_OFB, \ref CSP_FAST_CODE_E_CTR,
 * \ref CSP_FAST_CODE_D_ECB, \ref CSP_FAST_CODE_D_CBC, \ref CSP_FAST_CODE_D_CNT,
 * \ref CSP_FAST_CODE_D_CFB,  \ref CSP_FAST_CODE_D_OFB, \ref CSP_FAST_CODE_D_CTR, \ref CSP_FAST_CODE_MD_ECB,
 * \ref CSP_FAST_CODE_GR3411SP, \ref CSP_FAST_CODE_GR3411H, \ref CSP_FAST_CODE_GR3411HV, \ref CSP_FAST_CODE_HASH,
 * \ref CSP_FAST_CODE_HASH_2012, \ref CSP_FAST_CODE_HASH_2012HV, \ref CSP_FAST_CODE_IMIT, \ref CSP_FAST_CODE_IMIT_2015,
 * \ref CSP_FAST_CODE_MULT, в 1, если соответствующая функция использует быстрый код, и 0 - иначе.
 * В режиме пользователя следует вместо флага  CRYPT_FAST_CODE_ALL_FUNCTIONS
 * использовать CRYPT_FAST_CODE_ALL_USER_FUNCTIONS, а в режиме ядра ОС -
 * CRYPT_FAST_CODE_ALL_KERNEL_FUNCTIONS. На выходе флаг \ref CSP_FAST_CODE_GET_FN установлен в 1,
 * если быстрый код работает во всех выбранных функциях, и 0 если хотя бы одна
 * из выбранных функций не сработала.
 * Поведение не выбранных флагов не определено.
 *
 * \sa #CPGetProvParam (PP_FAST_CODE_FLAGS)
 * \{
 */

/*!
 *  \brief Флаг, возвращаемый функцией \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  Используется для определения полноты набора установленных быстрых функций.
 */
#define CSP_FAST_CODE_GET_FN	(1<<28)


/*!
 *  \brief Флаг, возвращаемый функцией \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  Используется для определения, может ли провайдер
 *  исполнять быстрый код на данной машине.
 */
#define CSP_FAST_CODE_GET_SETFN	(1<<27)

/*!
 *  \brief Флаг, возвращаемый функцией \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  Используется как флаг для проверки, какой код
 *  применяется в функции зашифрования по ECB.
 *  Равен 1 в случае быстрого кода данной функции,
 *  и 0 иначе.
 */
#define CSP_FAST_CODE_E_ECB	(1)

/*!
 *  \brief Флаг, возвращаемый функцией \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  Используется как флаг для проверки, какой код
 *  применяется в функции зашифрования по CBC.
 *  Равен 1 в случае быстрого кода данной функции,
 *  и 0 иначе.
 */
#define CSP_FAST_CODE_E_CBC	(1<<1)

/*!
 *  \brief Флаг, возвращаемый функцией \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  Используется как флаг для проверки, какой код
 *  применяется в функции зашифрования по CNT.
 *  Равен 1 в случае быстрого кода данной функции,
 *  и 0 иначе.
 */
#define CSP_FAST_CODE_E_CNT	(1<<2)

/*!
 *  \brief Флаг, возвращаемый функцией \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  Используется как флаг для проверки, какой код
 *  применяется в функции расшифрования по CNT.
 *  Равен 1 в случае быстрого кода данной функции,
 *  и 0 иначе.
 */
#define CSP_FAST_CODE_D_CNT	(1<<2)

/*!
 *  \brief Флаг, возвращаемый функцией \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  Используется как флаг для проверки, какой код
 *  применяется в функции зашифрования по CFB.
 *  Равен 1 в случае быстрого кода данной функции,
 *  и 0 иначе.
 */
#define CSP_FAST_CODE_E_CFB	(1<<3)

/*!
 *  \brief Флаг, возвращаемый функцией \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  Используется как флаг для проверки, какой код
 *  применяется в функции расшифрования по ECB.
 *  Равен 1 в случае быстрого кода данной функции,
 *  и 0 иначе.
 */
#define CSP_FAST_CODE_D_ECB	(1<<4)

/*!
 *  \brief Флаг, возвращаемый функцией \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  Используется как флаг для проверки, какой код
 *  применяется в функции расшифрования по CBC.
 *  Равен 1 в случае быстрого кода данной функции,
 *  и 0 иначе.
 */
#define CSP_FAST_CODE_D_CBC	(1<<5)

/*!
 *  \brief Флаг, возвращаемый функцией \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  Используется как флаг для проверки, какой код
 *  применяется в функции расшифрования по CFB.
 *  Равен 1 в случае быстрого кода данной функции,
 *  и 0 иначе.
 */
#define CSP_FAST_CODE_D_CFB	(1<<6)

/*!
 *  \brief Флаг, возвращаемый функцией \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  Используется как флаг для проверки, какой код
 *  применяется в функции маскирования ключа.
 *  Равен 1 в случае быстрого кода данной функции,
 *  и 0 иначе.
 */
#define CSP_FAST_CODE_MD_ECB	(1<<7)

/*!
 *  \brief Флаг, возвращаемый функцией \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  Используется как флаг для проверки, какой код
 *  применяется в упрощенной функции хэширования.
 *  Флаг устанавливается только в режиме ядра ОС.
 *  Равен 1 в случае быстрого кода данной функции,
 *  и 0 иначе.
 */
#define CSP_FAST_CODE_GR3411SP	(1<<8)

/*!
 *  \brief Флаг, возвращаемый функцией \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  Используется как флаг для проверки, какой код
 *  применяется в функции хэширования.
 *  Флаг устанавливается только в режиме ядра ОС.
 *  Равен 1 в случае быстрого кода данной функции,
 *  и 0 иначе.
 */
#define CSP_FAST_CODE_GR3411H	(1<<9)

/*!
 *  \brief Флаг, возвращаемый функцией \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  Используется как флаг для проверки, какой код
 *  применяется в функции проверки хэша.
 *  Флаг устанавливается только в режиме ядра ОС.
 *  Равен 1 в случае быстрого кода данной функции,
 *  и 0 иначе.
 */
#define CSP_FAST_CODE_GR3411HV	(1<<10)

/*!
 *  \brief Флаг, возвращаемый функцией \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  Используется как флаг для проверки, какой код
 *  применяется в функции хэш-преобразования.
 *  Равен 1 в случае быстрого кода данной функции,
 *  и 0 иначе.
 */
#define CSP_FAST_CODE_HASH	(1<<11)

/*!
 *  \brief Флаг, возвращаемый функцией \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  Используется как флаг для проверки, какой код
 *  применяется в функции выработки имитовставки.
 *  Равен 1 в случае быстрого кода данной функции,
 *  и 0 иначе.
 */
#define CSP_FAST_CODE_IMIT	(1<<12)

/*!
 *  \brief Флаг, возвращаемый функцией \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  Используется как флаг для проверки, какой код
 *  применяется в функции умножения.
 *  Равен 1 в случае быстрого кода данной функции,
 *  и 0 иначе.
 */
#define CSP_FAST_CODE_MULT	(1<<13)

/*!
 *  \brief Флаг, возвращаемый функцией \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  Используется как флаг для проверки, какой код применяется
 *  в функциях умножения в UNIX-оподобных системах.
 *  Равен 1 в случае быстрого кода данной функции,
 *  и 0 иначе.
 */
#define CSP_FAST_CODE_MULT_ATT	(1<<13)

/*!
*  \brief Флаг, возвращаемый функцией \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
*  Используется как флаг для проверки, какой код
*  применяется в функции хэш-преобразования по ГОСТ Р 34.11-2012.
*  Равен 1 в случае быстрого кода данной функции,
*  и 0 иначе.
*/
#define CSP_FAST_CODE_HASH_2012	    (1<<14)

/*!
*  \brief Флаг, возвращаемый функцией \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
*  Используется как флаг для проверки, какой код
*  применяется в функции проверки хэша по ГОСТ Р 34.11-2012.
*  Равен 1 в случае быстрого кода данной функции,
*  и 0 иначе.
*/
#define CSP_FAST_CODE_HASH_2012HV   (1<<15)

/*!
 *  \brief Флаг, возвращаемый функцией \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  Используется как флаг для проверки, используется ли SSSE3 код. Выставлен, если код не используется.
 */
#define CSP_FAST_CODE_DISABLE_SSSE3 (1<<16)

/*!
 *  \brief Флаг, возвращаемый функцией \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  Используется как флаг для проверки, используется ли AVX код. Выставлен, если код не используется.
 */
#define CSP_FAST_CODE_DISABLE_AVX (1<<17)

/*!
 *  \brief Флаг, возвращаемый функцией \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  Признак, что для захвата FPU используется TS-бит (Solaris, Linux).
 */
#define CSP_FAST_CODE_RT_TS (1<<18)

/*!
 *  \brief Флаг, возвращаемый функцией \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  Используется как флаг для проверки, какой код
 *  применяется в функции зашифрования по OFB.
 *  Равен 1 в случае быстрого кода данной функции,
 *  и 0 иначе.
 */
#define CSP_FAST_CODE_E_OFB	(1<<19)

/*!
 *  \brief Флаг, возвращаемый функцией \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  Используется как флаг для проверки, какой код
 *  применяется в функции расшифрования по OFB.
 *  Равен 1 в случае быстрого кода данной функции,
 *  и 0 иначе.
 */
#define CSP_FAST_CODE_D_OFB	(1<<19)

/*!
 *  \brief Флаг, возвращаемый функцией \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  Используется как флаг для проверки, какой код
 *  применяется в функции зашифрования по CTR.
 *  Равен 1 в случае быстрого кода данной функции,
 *  и 0 иначе.
 */
#define CSP_FAST_CODE_E_CTR	(1<<20)

/*!
 *  \brief Флаг, возвращаемый функцией \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  Используется как флаг для проверки, какой код
 *  применяется в функции расшифрования по CTR.
 *  Равен 1 в случае быстрого кода данной функции,
 *  и 0 иначе.
 */
#define CSP_FAST_CODE_D_CTR	(1<<20)

/*!
*  \brief Флаг, возвращаемый функцией \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
*  Используется как флаг для проверки, какой код
*  применяется в функции выработки имитовставки по ГОСТ Р 34.13-2015.
*  Равен 1 в случае быстрого кода данной функции,
*  и 0 иначе.
*/
#define CSP_FAST_CODE_IMIT_2015	(1<<21)

/*!
 * \brief Флаг, возвращаемый функцей \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 * Используется как флаг для проверки, какой код
 * применяется в функциях AES шифрования.
 * Равен 1 в случае быстрого кода данной функции,
 * и 0 иначе.
 */
#define CSP_FAST_CODE_AESNI (1<<22)

 /*!
 * \brief Флаг, возвращаемый функцей \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 * Используется как флаг для проверки, какой код
 * применяется в функциях RSA.
 * Равен 1 в случае быстрого кода данной функции,
 * и 0 иначе.
 */
#define CSP_FAST_CODE_RSA (1<<23)

 /*!
 * \brief Флаг, возвращаемый функцей \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 * Используется как флаг для проверки, какой код
 * применяется в функциях GCM шифрования.
 * Равен 1 в случае быстрого кода данной функции,
 * и 0 иначе.
 */
#define CSP_FAST_CODE_GHASH (1<<24)

/*!
 * \brief Флаг, возвращаемый функцей \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 * Используется как флаг для проверки, какой код
 * применяется в функциях SHA2 хэширования.
 * Равен 1 в случае быстрого кода данной функции,
 * и 0 иначе.
 */
#define CSP_FAST_CODE_SHA2 (1<<25)

/*!
 * \brief Флаг, возвращаемый функцей \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 * Используется как флаг для проверки, какой код
 * применяется в функциях SHA1 хэширования.
 * Равен 1 в случае быстрого кода данной функции,
 * и 0 иначе.
 */
#define CSP_FAST_CODE_SHA1 (1<<26)

 /*!
  * \brief Флаг, возвращаемый функцей \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
  * Используется как флаг для проверки, какой код
  * применяется в функции аутентификации MGM.
  * Равен 1 в случае быстрого кода данной функции,
  * и 0 иначе.
  */
#define CSP_FAST_CODE_MGM_AUTH (1<<29)

  /*!
   *  \brief Флаг, возвращаемый функцией \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
   *  Используется как флаг для проверки, используется ли AVX2 код. Выставлен, если код не используется.
   */
#define CSP_FAST_CODE_DISABLE_AVX2 (1<<30)

/*!
 *  \brief Набор флагов, возвращаемый функцией \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  Группирует все флаги функций зашифрования.
 */
#define CSP_FAST_CODE_ALL_ENCRYPT (CSP_FAST_CODE_E_ECB|CSP_FAST_CODE_E_CBC|CSP_FAST_CODE_E_CNT|CSP_FAST_CODE_E_CFB|CSP_FAST_CODE_E_OFB|CSP_FAST_CODE_E_CTR)


/*!
 *  \brief Набор флагов, возвращаемый функцией \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  Группирует все флаги функций расшифрования.
 */
#define CSP_FAST_CODE_ALL_DECRYPT (CSP_FAST_CODE_D_ECB|CSP_FAST_CODE_D_CBC|CSP_FAST_CODE_D_CNT|CSP_FAST_CODE_D_CFB|CSP_FAST_CODE_D_OFB|CSP_FAST_CODE_D_CTR)


/*!
 *  \brief Набор флагов, возвращаемый функцией \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  Группирует все флаги функций хэширования.
 */
#define CSP_FAST_CODE_ALL_HASH (CSP_FAST_CODE_HASH|CSP_FAST_CODE_GR3411SP|CSP_FAST_CODE_GR3411H|CSP_FAST_CODE_GR3411HV|CSP_FAST_CODE_HASH_2012|CSP_FAST_CODE_HASH_2012HV)

/*!
 *  \brief Набор флагов, возвращаемый функцией \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  Группирует все флаги функций умножения.
 */
#define CSP_FAST_CODE_ALL_MULT (CSP_FAST_CODE_MULT|CSP_FAST_CODE_MULT_ATT)

/*!
 *  \brief Набор флагов, возвращаемый функцией \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  Группирует все флаги функций шифрования.
 */
#define CSP_FAST_CODE_ALL_CRYPT (CSP_FAST_CODE_ALL_ENCRYPT|CSP_FAST_CODE_ALL_DECRYPT|CSP_FAST_CODE_MD_ECB|CSP_FAST_CODE_IMIT|CSP_FAST_CODE_IMIT_2015|CSP_FAST_CODE_MGM_AUTH)

/*!
 *  \brief Набор флагов, возвращаемый функцией \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  Группирует все флаги функций симметричной зарубежной криптографии.
 */
#define CSP_FAST_CODE_CIPHER_FOREIGN (CSP_FAST_CODE_AESNI | CSP_FAST_CODE_GHASH)

 /*!
 *  \brief Набор флагов, возвращаемый функцией \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  Группирует все флаги функций хэширования зарубежной криптографии.
 */
#define CSP_FAST_CODE_HASH_FOREIGN (CSP_FAST_CODE_SHA1 | CSP_FAST_CODE_SHA2)

/*!
 *  \brief Набор флагов, возвращаемый функцией \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  Группирует все флаги функций зарубежной криптографии.
 */
#define CSP_FAST_CODE_ALL_FOREIGN (CSP_FAST_CODE_CIPHER_FOREIGN | CSP_FAST_CODE_HASH_FOREIGN | CSP_FAST_CODE_RSA)

/*!
 *  \brief Набор флагов, возвращаемый функцией \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  Группирует все флаги переключаемых функций криптопровайдера.
 */
#define CSP_FAST_CODE_ALL_FUNCTIONS (CSP_FAST_CODE_ALL_CRYPT|CSP_FAST_CODE_ALL_HASH|CSP_FAST_CODE_ALL_MULT | CSP_FAST_CODE_ALL_FOREIGN)

/*!
 *  \brief Набор флагов, возвращаемый функцией \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  Группирует все флаги переключаемых функций
 *  криптопровайдера режима ядра ОС.
 */
#define CSP_FAST_CODE_ALL_KERNEL_FUNCTIONS (CSP_FAST_CODE_ALL_CRYPT|CSP_FAST_CODE_ALL_HASH|CSP_FAST_CODE_RSA|CSP_FAST_CODE_HASH_FOREIGN)

/*!
 *  \brief Набор флагов, возвращаемый функцией \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  Группирует все флаги переключаемых функций
 *  криптопровайдера пользовательского режима.
 */
#define CSP_FAST_CODE_ALL_USER_FUNCTIONS (CSP_FAST_CODE_ALL_CRYPT|CSP_FAST_CODE_HASH|CSP_FAST_CODE_HASH_2012|CSP_FAST_CODE_HASH_2012HV|CSP_FAST_CODE_ALL_MULT|CSP_FAST_CODE_ALL_FOREIGN)


/*!
 * \brief Флаг, используемый при вызове \ref CPGetProvParam (PP_FAST_CODE_FLAGS), запрашивает вариант кода
 *  для всех функций провайдера в режиме ядра ОС.
 */
#define CRYPT_FAST_CODE_ALL_KERNEL_FUNCTIONS	1

/*!
 * \brief Флаг, используемый при вызове \ref CPGetProvParam (PP_FAST_CODE_FLAGS), запрашивает вариант кода
 * для всех функций провайдера в режиме пользователя.
 */
#define CRYPT_FAST_CODE_ALL_USER_FUNCTIONS	2

/*!
 * \brief Флаг, используемый при вызове \ref CPGetProvParam (PP_FAST_CODE_FLAGS), запрашивает вариант кода
 * для всех функций провайдера.
 */
#define CRYPT_FAST_CODE_ALL_FUNCTIONS		(CRYPT_FAST_CODE_ALL_KERNEL_FUNCTIONS|CRYPT_FAST_CODE_ALL_USER_FUNCTIONS)

/*!
 * \brief Флаг, используемый при вызове \ref CPGetProvParam (PP_FAST_CODE_FLAGS), запрашивает
 * результат определения процессора.
 */
#define CRYPT_FAST_CODE_GET_SETFN		8


/*!
 *  \brief Возможное значение аргумента op_type функции \ref CPC_Kernel_Fpu_Begin_Callback.
 *  Означает, что запрос захвата FPU произошел в функции нераспараллеливаемого шифрования.
 *  Также задает значение идентификатора набора функций нераспараллеливаемого шифрования,
 *  использующих расширение MMX (только для x86 архитектуры).
 */
#define CSP_OPERATION_CIPHER1	(CSP_FAST_CODE_E_CFB | CSP_FAST_CODE_E_CBC)

/*!
 *  \brief Возможное значение аргумента op_type функции \ref CPC_Kernel_Fpu_Begin_Callback.
 *  Означает, что запрос захвата FPU произошел в функции распараллеливаемого шифрования.
 *  Также задает значение идентификатора набора функций распараллеливаемого шифрования,
 *  использующих расширения MMX, SSE2, SSSE3, AVX и CLMUL. В режиме x64 дополнительно используется AVX2.
 *  В режиме ядра x64 MMX расширение не используется.
 */
#define CSP_OPERATION_CIPHER2	(CSP_FAST_CODE_E_ECB | CSP_FAST_CODE_E_CNT | CSP_FAST_CODE_E_OFB | CSP_FAST_CODE_E_CTR | CSP_FAST_CODE_D_ECB | CSP_FAST_CODE_D_CBC | CSP_FAST_CODE_D_CNT | CSP_FAST_CODE_D_OFB | CSP_FAST_CODE_D_CTR | CSP_FAST_CODE_D_CFB | CSP_FAST_CODE_MD_ECB | CSP_FAST_CODE_MGM_AUTH)


/*!
 *  \brief Возможное значение аргумента op_type функции \ref CPC_Kernel_Fpu_Begin_Callback.
 *  Означает, что запрос захвата FPU произошел в функции выработки имитовставки.
 *  Также задает значение идентификатора набора функций выработки имитовставки,
 *  использующих расширение MMX (только для x86 архитектуры).
 */
#define CSP_OPERATION_IMIT	(CSP_FAST_CODE_IMIT | CSP_FAST_CODE_IMIT_2015)

/*!
 *  \brief Возможное значение аргумента op_type функции \ref CPC_Kernel_Fpu_Begin_Callback.
 *  Означает, что запрос захвата FPU произошел в функции хэширования. В данном случае
 *  необходимо сохранять не только регистры ST0 - ST7, но и XMM0 - XMM7.
 *  Также задает значение идентификатора набора функций хэширования,
 *  использующих расширения MMX и SSE2.
 *  В режиме ядра x64 MMX расширение не используется.
 */
#define CSP_OPERATION_HASH	(CSP_FAST_CODE_ALL_HASH)

/*!
 *  \brief Битовая маска для включения/выключения кода MMX в функции умножения.
 *  Задает значение идентификатора набора функций умножения по модулю P, 
 *  использующих расширения MMX и SSE2. Применяется только в пользовательском режиме.
 */
#define CSP_OPERATION_MULT	(CSP_FAST_CODE_ALL_MULT)

 /*!
  *  \brief Битовая маска для включения/выключения быстрого кода функции MGM_Auth режима MGM.
  *  Задает значение логической суммы всех идентификаторов наборов функций,
  *  использующих расширения SSSE3, AVX и CLMUL. В режиме x64 дополнительно используется AVX2.
  */
#define CSP_OPERATION_MGM_AUTH	(CSP_FAST_CODE_MGM_AUTH)

/*!
 *  \brief Битовая маска для включения/выключения быстрого кода для функции GHASH режима GCM зарубежной криптографии.
 *  Задает значение логической суммы всех идентификаторов наборов функций,
 *  использующих расширения MMX или SSE2 + CLMUL в режиме x86 и SSSE3 + CLMUL или AVX + CLMUL в режиме x64.
 *  Применяется только в пользовательском режиме.
 */
#define CSP_OPERATION_GHASH	(CSP_FAST_CODE_GHASH)

/*!
 *  \brief Битовая маска для включения/выключения быстрого кода для AES.
 *  Задает значение логической суммы всех идентификаторов наборов функций,
 *  использующих расширения MMX, SSE2, AES-NI. Применяется только в пользовательском режиме.
 */
#define CSP_OPERATION_AESNI	(CSP_FAST_CODE_AESNI)

 /*!
 *  \brief Битовая маска для включения/выключения быстрого кода для зарубежного шифрования.
 *  Задает значение логической суммы всех идентификаторов наборов функций,
 *  использующих расширения AESNI, MMX или SSE2 + CLMUL в режиме x86 и
 *  AESNI, SSSE3 + CLMUL или AVX + CLMUL в режиме x64.
 *  Применяется только в пользовательском режиме.
 */
#define CSP_OPERATION_CIPHER_FOREIGN  (CSP_OPERATION_GHASH | CSP_OPERATION_AESNI)

 /*!
 *  \brief Битовая маска для включения/выключения быстрого кода для зарубежного хэширования.
 *  Задает значение логической суммы всех идентификаторов наборов функций,
 *  использующих расширения SSE2, SSSE3, AVX, BMI1, BMI2, SHAExtenson. В режиме x64 дополнительно используется AVX2.
 */
#define CSP_OPERATION_HASH_FOREIGN  (CSP_FAST_CODE_SHA1 | CSP_FAST_CODE_SHA2)

/*!
 *  \brief Битовая маска для включения/выключения быстрого кода для RSA.
 *  Задает значение логической суммы всех идентификаторов наборов функций,
 *  использующих расширения ADX и BMI2.
 */
#define CSP_OPERATION_RSA	(CSP_FAST_CODE_RSA)

/*!
 *  \brief Битовая маска для включения/выключения быстрого кода для функций зарубежной криптографии.
 *  Задает значение логической суммы всех идентификаторов наборов функций,
 *  использующих расширения MMX, SSE2, SSSE3, AVX, SHAExtenson, CLMUL, AES-NI, ADX, BMI1, BMI2. В режиме x64 дополнительно используется AVX2.
 */
#define CSP_OPERATION_FOREIGN   (CSP_OPERATION_CIPHER_FOREIGN | CSP_OPERATION_HASH_FOREIGN | CSP_OPERATION_RSA)

/*!
 *  \brief Битовая маска для включения/выключения кода быстрого кода во всех функциях.
 *  Задает значение логической суммы всех идентификаторов наборов функций,
 *  использующих MMX, SSE2, SSSE3, AVX, SHAExtenson, CLMUL, AES-NI, ADX, BMI1, BMI2. В режиме x64 дополнительно используется AVX2.
 */
#define CSP_OPERATION_ALL	(CSP_OPERATION_MULT | CSP_OPERATION_HASH | CSP_OPERATION_IMIT | CSP_OPERATION_CIPHER2 | CSP_OPERATION_CIPHER1 | CSP_OPERATION_FOREIGN)

/*!
 *  \brief Битовая маска, означающая неопределенную установку функций. Применяется, если 
 *  нужно установить набор функций по умолчанию для данного процессора.
 */
#define CSP_OPERATION_UNDEF	(0xFFFFFFFF)


/*! \} */

typedef struct _CRYPT_LCD_QUERY_PARAM {
  const char *message;
} CRYPT_LCD_QUERY_PARAM;


//Deprecated Defines
#if !(defined(CPCSP_C_SOURCE ) && CPCSP_C_SOURCE - 0 < 363) 
#undef CP_GR3410_94_PROV
#undef CP_KC1_GR3410_94_PROV
#undef CP_KC2_GR3410_94_PROV

#undef PROV_GOST_DH
#undef PROV_GOST_94_DH

#undef CALG_GR3410
#undef CALG_DH_EX_SF
#undef CALG_DH_EX_EPHEM
#undef CALG_DH_EX

#endif

#if !defined(CPCSP_USE_NON_STANDART_OIDS) && !(defined(CPCSP_C_SOURCE ) && CPCSP_C_SOURCE - 0 < 36) 

#undef szOID_CP_GOST_R3410
#undef szOID_CP_DH_EX
#undef szOID_CP_GOST_R3410_94_ESDH

/* OIDs for HASH */
#undef szOID_GostR3411_94_TestParamSet
#undef szOID_GostR3411_94_CryptoPro_B_ParamSet
#undef szOID_GostR3411_94_CryptoPro_C_ParamSet
#undef szOID_GostR3411_94_CryptoPro_D_ParamSet

/* OIDs for Crypt */
#undef szOID_Gost28147_89_TestParamSet
#undef szOID_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet
#undef szOID_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet
#undef szOID_Gost28147_89_CryptoPro_RIC_1_ParamSet

/* OID for Signature 1024*/
#undef szOID_GostR3410_94_CryptoPro_A_ParamSet
#undef szOID_GostR3410_94_CryptoPro_B_ParamSet
#undef szOID_GostR3410_94_CryptoPro_C_ParamSet
#undef szOID_GostR3410_94_CryptoPro_D_ParamSet

/* OID for Signature 512*/
#undef szOID_GostR3410_94_TestParamSet

/* OID for DH 1024*/
#undef szOID_GostR3410_94_CryptoPro_XchA_ParamSet
#undef szOID_GostR3410_94_CryptoPro_XchB_ParamSet
#undef szOID_GostR3410_94_CryptoPro_XchC_ParamSet

/* OID for EC signature */
#undef szOID_GostR3410_2001_TestParamSet

#endif



/*! \defgroup ProCSPEx Дополнительные параметры и определения
 *\ingroup ProCSP
 * Данный раздел содержит определения идентификаторов и параметров,
 * используемых в криптопровайдере "КриптоПро CSP".
 *
 * \{
 */

/*! \page DP1 Идентификаторы алгоритмов криптопровайдера
 *
 * <table>
 * <tr><th>Идентификатор</th><th>Описание идентификатора</th></tr>
 * <tr><td>CALG_GR3411</td><td>Идентификатор алгоритма хэширования по ГОСТ Р 34.11-94.</td></tr>
 * <tr><td>CALG_GR3411_2012_256</td><td>Идентификатор алгоритма хэширования в соответствии с ГОСТ Р 34.11-2012, длина выхода 256 бит.</td></tr>
 * <tr><td>CALG_GR3411_2012_512</td><td>Идентификатор алгоритма хэширования в соответствии с ГОСТ Р 34.11-2012, длина выхода 512 бит.</td></tr>
 * <tr><td>CALG_G28147_MAC</td><td>Идентификатор алгоритма имитозащиты по ГОСТ 28147-89.</td></tr>
 * <tr><td>CALG_G28147_IMIT </td><td>То же самое, что и CALG_G28147_MAC (устаревшая версия).</td></tr>
 * <tr><td>CALG_GR3413_2015_M_IMIT</td><td>Идентификатор алгоритма имитозащиты в соответствии с ГОСТ Р 34.13-2015 и сессионным ключом CALG_GR3412_2015_M (Магма).</td></tr>
 * <tr><td>CALG_GR3413_2015_K_IMIT</td><td>Идентификатор алгоритма имитозащиты в соответствии с ГОСТ Р 34.13-2015 и сессионным ключом CALG_GR3412_2015_К (Кузнечик).</td></tr>
 * <tr><td> CALG_GR3410EL </td><td> Идентификатор алгоритма ЭЦП по ГОСТ Р 34.10-2001.</td></tr>
 * <tr><td> CALG_GR3410_12_256 </td><td> Идентификатор алгоритма ЭЦП по ГОСТ Р 34.10-2012 (256 бит).</td></tr>
 * <tr><td> CALG_GR3410_12_512 </td><td> Идентификатор алгоритма ЭЦП по ГОСТ Р 34.10-2012 (512 бит).</td></tr>
 * <tr><td> CALG_GR3411_HMAC </td><td> Идентификатор алгоритма ключевого хэширования на базе алгоритма ГОСТ Р 34.11-94 и сессионного ключа CALG_G28147.</td></tr>
 * <tr><td> CALG_GR3411_2012_256_HMAC </td><td> Идентификатор алгоритма ключевого хэширования на базе алгоритма ГОСТ Р 34.11-2012 и сессионного ключа CALG_G28147, длина выхода 256 бит.</td></tr>
 * <tr><td> CALG_GR3411_2012_512_HMAC </td><td> Идентификатор алгоритма ключевого хэширования на базе алгоритма ГОСТ Р 34.11-2012 и сессионного ключа CALG_G28147, длина выхода 512 бит.</td></tr>
 * <tr><td>CALG_G28147</td><td>Идентификатор алгоритма шифрования по ГОСТ 28147-89. </td></tr>
 * <tr><td>CALG_GR3412_2015_M</td><td>Идентификатор алгоритма шифрования по ГОСТ Р 34.12-2015 Магма. </td></tr>
 * <tr><td>CALG_GR3412_2015_K</td><td>Идентификатор алгоритма шифрования по ГОСТ Р 34.12-2015 Кузнечик. </td></tr>
 * <tr><td>CALG_SYMMETRIC_512</td><td>Идентификатор алгоритма выработки ключа парной связи по Диффи-Хеллману с длиной выхода 512 бит.</td></tr>
 * <tr><td>CALG_GOST_GENERIC_SECRET</td><td>Идентификатор алгоритма ключа произвольной длины.</td></tr>
 * <tr><td>CALG_DH_EL_SF </td><td>Идентификатор алгоритма обмена ключей по Диффи-Хеллману на базе закрытого ключа пользователя. Открытый ключ получается по ГОСТ Р 34.10 2001.</td></tr>
 * <tr><td>CALG_DH_EL_EPHEM</td><td> Идентификатор алгоритма обмена ключей по Диффи-Хеллману на базе закрытого ключа эфемерной пары. Открытый ключ получается по ГОСТ Р 34.10 2001.</td></tr>
 * <tr><td>CALG_DH_GR3410_12_256_SF</td><td>Идентификатор алгоритма обмена ключей по Диффи-Хеллману на базе закрытого ключа пользователя. Открытый ключ получается по ГОСТ Р 34.10 2012 (256 бит).</td></tr>
 * <tr><td>CALG_DH_GR3410_12_256_EPHEM</td><td> Идентификатор алгоритма обмена ключей по Диффи-Хеллману на базе закрытого ключа эфемерной пары. Открытый ключ получается по ГОСТ Р 34.10 2012 (256 бит).</td></tr>
 * <tr><td>CALG_DH_GR3410_12_512_SF</td><td>Идентификатор алгоритма обмена ключей по Диффи-Хеллману на базе закрытого ключа пользователя. Открытый ключ получается по ГОСТ Р 34.10 2012 (512 бит).</td></tr>
 * <tr><td>CALG_DH_GR3410_12_512_EPHEM</td><td> Идентификатор алгоритма обмена ключей по Диффи-Хеллману на базе закрытого ключа эфемерной пары. Открытый ключ получается по ГОСТ Р 34.10 2012 (512 бит).</td></tr>
 * <tr><td>CALG_PRO_AGREEDKEY_DH</td><td>Идентификатор алгоритма выработки ключа парной связи по Диффи-Хеллману. </td></tr>
 * <tr><td>CALG_PRO_EXPORT </td><td> Идентификатор алгоритма защищённого экспорта ключа.</td></tr>
 * <tr><td>CALG_PRO12_EXPORT </td><td> Идентификатор алгоритма защищённого экспорта ключа по рекомендациям ТК26 (обязателен для экспорта закрытых ключей ГОСТ Р 34.10-2012).</td></tr>
 * <tr><td>CALG_SIMPLE_EXPORT </td><td>Идентификатор алгоритма простого экспорта ключа. </td></tr>
 * <tr><td>CALG_KEXP_2015_M </td><td> Идентификатор алгоритма защищённого экспорта ключа ГОСТ Р 34.12-2015 Магма.</td></tr>
 * <tr><td>CALG_KEXP_2015_K </td><td> Идентификатор алгоритма защищённого экспорта ключа ГОСТ Р 34.12-2015 Кузнечик.</td></tr>
 * <tr><td>CALG_MGM_EXPORT_M</td><td>Идентификатор алгоритма экспорта/импорта ключей с использованием алгоритма ГОСТ Р 34.12-2015 Магма в режиме MGM.</td></tr>
 * <tr><td>CALG_MGM_EXPORT_K</td><td>Идентификатор алгоритма экспорта/импорта ключей с использованием алгоритма ГОСТ Р 34.12-2015 Кузнечик в режиме MGM.</td></tr>
 * <tr><td> CALG_TLS1PRF</td><td>Идентификатор алгоритма "производящей функции" (PRF) протокола TLS 1.0 на основе алгоритма хэширования в соответствии с ГОСТ Р 34.11-94.</td></tr>
 * <tr><td> СALG_TLS1PRF_2012_256</td><td>Идентификатор алгоритма "производящей функции" (PRF) протокола TLS 1.0 на основе алгоритма хэширования в соответствии с ГОСТ Р 34.11-2012.</td></tr>
 * <tr><td> CALG_TLS1_MASTER_HASH</td><td>Идентификатор алгоритма выработки объекта MASTER_HASH протокола TLS 1.0 на основе алгоритма хэширования в соответствии с ГОСТ Р 34.11-94.</td></tr>
 * <tr><td> CALG_TLS1_MASTER_HASH_2012_256</td><td>Идентификатор алгоритма выработки объекта MASTER_HASH протокола TLS 1.0 на основе алгоритма хэширования в соответствии с ГОСТ Р 34.11-2012.</td></tr>
 * <tr><td> CALG_TLS1_MAC_KEY</td><td>Идентификатор алгоритма выработки ключа имитозащиты протокола TLS 1.0. </td></tr>
 * <tr><td> CALG_TLS1_ENC_KEY </td><td> Идентификатор алгоритма выработки ключа шифрования протокола TLS 1.0.</td></tr>
 * <tr><td> CALG_PBKDF2_94_256</td><td>Идентификатор алгоритма выработки ключа из пароля на основе алгоритма хэширования в соответвии с ГОСТ Р 34.11-94, длина выхода 256 бит.</td></tr>
 * <tr><td> CALG_PBKDF2_2012_256</td><td>Идентификатор алгоритма выработки ключа из пароля на основе алгоритма хэширования в соответвии с ГОСТ Р 34.11-2012, длина выхода 256 бит.</td></tr>
 * <tr><td> CALG_PBKDF2_2012_512</td><td>Идентификатор алгоритма выработки ключа из пароля на основе алгоритма хэширования в соответвии с ГОСТ Р 34.11-2012, длина выхода 512 бит.</td></tr>
 * <tr><td> CALG_PRO_DIVERS</td><td>Идентификатор алгоритма КриптоПро диверсификации ключа по RFC 4357.</td></tr>
 * <tr><td> CALG_PRO12_DIVERS</td><td>Идентификатор алгоритма КриптоПро диверсификации ключа по рекомендациям ТК26.</td></tr>
 * <tr><td> CALG_RIC_DIVERS</td><td>Идентификатор алгоритма РИК диверсификации ключа. </td></tr>
 * <tr><td> CALG_KDF_TREE_GOSTR3411_2012_256</td><td>Идентификатор алгоритма диверсификации ключа по рекомендациям ТК26 с использованием древовидной структуры. </td></tr>
 *</table>
 */

/*! \page DP2 Режимы шифрования
 * <table>
 * <tr><th>Параметр</th><th>Значение параметра</th></tr>
 * <tr><td>CRYPT_PROMIX_MODE </td><td>Задание режимов шифрования/расшифрования по ГОСТ 28147-89 с преобразованием ключа в процессе обработки информации</td></tr>
 * <tr><td>CRYPT_ACPKM_MODE </td><td>Задание режимов шифрования/расшифрования по ГОСТ Р 34.12-2015 с преобразованием ключа в процессе обработки информации</td></tr>
 * <tr><td>CRYPT_SIMPLEMIX_MODE </td><td>Задание режимов шифрования/расшифрования по ГОСТ 28147-89/ГОСТ Р 34.12-2015 без преобразования ключа в процессе обработки информации</td></tr>
 *</table>
*/

/*! \page DP3 Параметры криптопровайдера
 * <table>
 * <tr><th>Параметр</th><th>Значение параметра</th></tr>
 * <tr><td>PP_ENUMOIDS_EX</td><td>Получает перечень идентификаторов объектов, используемых в криптопровайдере</td></tr>
 * <tr><td>PP_HASHOID</td><td>Получает и/или устанавливает заданный в контейнере OID узла замены функции хэширования ГОСТ Р 34.11-94 для наследования криптографическими объектами</td></tr>
 * <tr><td>PP_CIPHEROID</td><td>Получает и/или устанавливает заданный в контейнере OID узла замены алгоритма шифрования ГОСТ 28147-89 для наследования криптографическими объектами </td></tr>
 * <tr><td>PP_SIGNATUREOID</td><td>Получает и/или устанавливает заданный в контейнере OID параметров цифровой подписи - в зависимости от типа провайдера </td></tr>
 * <tr><td>PP_DHOID</td><td>Получает и/или устанавливает заданный в контейнере OID параметров алгоритма Диффи-Хеллмана в зависимости от типа провайдера </td></tr>
 * <tr><td>PP_RANDOM</td><td>Получает или устанавливает последовательность случайных чисел для инициализации программного ДСЧ</td></tr>
 * <tr><td>PP_ENUM_HASHOID</td><td>Получает перечень идентификаторов криптографических объектов, связанных с функцией хэширования ГОСТ Р 34.11-94 </td></tr>
 * <tr><td>PP_ENUM_CIPHEROID</td><td>Получает перечень идентификаторов криптографических объектов, связанных с функцией шифрования ГОСТ 28147-89  </td></tr>
 * <tr><td>PP_ENUM_SIGNATUREOID</td><td>Получает перечень идентификаторов криптографических объектов, связанных с функцией цифровой подписи, в зависимости от типа провайдера </td></tr>
 * <tr><td>PP_ENUM_DHOID</td><td>Получает перечень идентификаторов криптографических объектов, связанных с алгоритмом Диффи-Хеллмана, в зависимости от типа провайдера </td></tr>
 *</table>
*/

/*! \page DP4 Параметры дополнительных ключевых блобов
 * <table>
 * <tr><th>Параметр</th><th>Значение параметра</th></tr>
 * <tr><td>DIVERSKEYBLOB</td><td>Тип ключевого блоба для диверсификации ключей с помощью
    функции CPImportKey в режиме CALG_PRO_DIVERS, CALG_RIC_DIVERS или CALG_PRO12_DIVERS</td></tr>
 * <tr><td>CRYPT_KDF_TREE_DIVERSBLOB</td><td>Тип ключевого блоба для диверсификации ключей с помощью
    функции CPImportKey в режиме CALG_KDF_TREE_GOSTR3411_2012_256</td></tr>
 *</table>
*/

/*! \page DP8 Групповые идентификаторы криптографических параметров алгоритмов
 * <table>
 * <tr><th>Параметр</th><th>Индекс</th><th>Значение параметра</th></tr>
 * <tr><td>szOID_CP_GOST_28147</td><td>"1.2.643.2.2.21"</td><td>Алгоритм шифрования ГОСТ 28147-89</td></tr>
 * <tr><td>szOID_CP_GOST_R3412_2015_M</td><td>"1.2.643.7.1.1.5.1"</td><td>Алгоритм шифрования ГОСТ Р 34.12-2015 Магма</td></tr>
 * <tr><td>szOID_CP_GOST_R3412_2015_K</td><td>"1.2.643.7.1.1.5.2"</td><td>Алгоритм шифрования ГОСТ Р 34.12-2015 Кузнечик</td></tr>
 * <tr><td>szOID_CP_GOST_R3411</td><td>"1.2.643.2.2.9"</td><td>Функция хэширования ГОСТ Р 34.11-94</td></tr>
 * <tr><td>szOID_CP_GOST_R3411_12_256</td><td>"1.2.643.7.1.1.2.2"</td><td>Функция хэширования ГОСТ Р 34.11-2012, длина выхода 256 бит</td></tr>
 * <tr><td>szOID_CP_GOST_R3411_12_512</td><td>"1.2.643.7.1.1.2.3"</td><td>Функция хэширования ГОСТ Р 34.11-2012, длина выхода 512 бит</td></tr>
 * <tr><td>szOID_CP_GOST_R3410EL</td><td>"1.2.643.2.2.19"</td><td>Алгоритм ГОСТ Р 34.10-2001</td></tr>
 * <tr><td>szOID_CP_GOST_R3410_12_256</td><td>"1.2.643.7.1.1.1.1"</td><td>Алгоритм ГОСТ Р 34.10-2012 для ключей длины 256 бит</td></tr>
 * <tr><td>szOID_CP_GOST_R3410_12_512</td><td>"1.2.643.7.1.1.1.2"</td><td>Алгоритм ГОСТ Р 34.10-2012 для ключей длины 512 бит</td></tr>
 * <tr><td>szOID_CP_DH_EL</td><td>"1.2.643.2.2.98"</td><td>Алгоритм Диффи-Хеллмана на базе эллиптической кривой</td></tr>
 * <tr><td>szOID_CP_DH_12_256</td><td>"1.2.643.7.1.1.6.1"</td><td>Алгоритм Диффи-Хеллмана на базе эллиптической кривой для ключей длины 256 бит</td></tr>
 * <tr><td>szOID_CP_DH_12_512</td><td>"1.2.643.7.1.1.6.2"</td><td>Алгоритм Диффи-Хеллмана на базе эллиптической кривой для ключей длины 512 бит</td></tr>
 * <tr><td>szOID_CP_GOST_R3411_R3410EL</td><td>"1.2.643.2.2.3"</td><td>Алгоритм цифровой подписи ГОСТ Р 34.10-2001 с алгоритмом хэширования ГОСТ Р 34.11-94</td></tr>
 * <tr><td>szOID_CP_GOST_R3411_12_256_R3410</td><td>"1.2.643.7.1.1.3.2"</td><td>Алгоритм цифровой подписи ГОСТ Р 34.10-2012 для ключей длины 256 бит с алгоритмом хэширования ГОСТ Р 34.11-2012, длина выхода 256 бит</td></tr>
 * <tr><td>szOID_CP_GOST_R3411_12_512_R3410</td><td>"1.2.643.7.1.1.3.3"</td><td>Алгоритм цифровой подписи ГОСТ Р 34.10-2012 для ключей длины 512 бит с алгоритмом хэширования ГОСТ Р 34.11-2012, длина выхода 512 бит</td></tr>
 * <tr><td>szOID_KP_TLS_PROXY</td><td>"1.2.643.2.2.34.1"</td><td>Аудит TLS-трафика</td></tr>
 * <tr><td>szOID_KP_RA_CLIENT_AUTH</td><td>"1.2.643.2.2.34.2"</td><td>Идентификация пользователя на центре регистрации</td></tr>
 * <tr><td>szOID_KP_WEB_CONTENT_SIGNING</td><td>"1.2.643.2.2.34.3"</td><td>Подпись содержимого сервера Интернет</td></tr>
 *</table>
*/

/*! \ingroup ProCSPEx
 * \page CP_PARAM_OIDS Идентификаторы криптографических параметров алгоритмов
 * <table>
 * <tr><th>Параметр</th><th>Индекс</th><th>Значение параметра</th></tr>
 * <tr><td>szOID_GostR3411_94_TestParamSet</td><td>"1.2.643.2.2.30.0"</td><td>Тестовый узел замены</td></tr>
 * <tr><td>szOID_GostR3411_94_CryptoProParamSet</td><td>"1.2.643.2.2.30.1"</td><td>Узел замены функции хэширования по умолчанию, вариант "Верба-О"</td></tr>
 * <tr><td>szOID_GostR3411_94_CryptoPro_B_ParamSet</td><td>"1.2.643.2.2.30.2"</td><td>Узел замены функции хэширования, вариант 1</td></tr>
 * <tr><td>szOID_GostR3411_94_CryptoPro_C_ParamSet</td><td>"1.2.643.2.2.30.3"</td><td>Узел замены функции хэширования, вариант 2</td></tr>
 * <tr><td>szOID_GostR3411_94_CryptoPro_D_ParamSet</td><td>"1.2.643.2.2.30.4"</td><td>Узел замены функции хэширования, вариант 3</td></tr>
 * <tr><td>szOID_Gost28147_89_TestParamSet</td><td>"1.2.643.2.2.31.0"</td><td>Тестовый узел замены алгоритма шифрования</td></tr>
 * <tr><td>szOID_Gost28147_89_CryptoPro_A_ParamSet</td><td>"1.2.643.2.2.31.1"</td><td>Узел замены алгоритма шифрования по умолчанию, вариант "Верба-О"</td></tr>
 * <tr><td>szOID_Gost28147_89_CryptoPro_B_ParamSet</td><td>"1.2.643.2.2.31.2"</td><td>Узел замены алгоритма шифрования, вариант 1</td></tr>
 * <tr><td>szOID_Gost28147_89_CryptoPro_C_ParamSet</td><td>"1.2.643.2.2.31.3"</td><td>Узел замены алгоритма шифрования, вариант 2</td></tr>
 * <tr><td>szOID_Gost28147_89_CryptoPro_D_ParamSet</td><td>"1.2.643.2.2.31.4"</td><td>Узел замены алгоритма шифрования, вариант 3</td></tr>
 * <tr><td>szOID_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet</td><td>"1.2.643.2.2.31.5" </td><td>Узел замены, вариант карты КриптоРИК</tr>
 * <tr><td>szOID_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet</td><td>"1.2.643.2.2.31.6" </td><td>Узел замены, используемый при шифровании с хэшированием</td></tr>
 * <tr><td>szOID_Gost28147_89_TC26_A_ParamSet</td><td>"1.2.643.2.2.31.12" </td><td>Узел замены алгоритма шифрования, вариант ТК26 2</td></tr>
 * <tr><td>szOID_Gost28147_89_TC26_B_ParamSet</td><td>"1.2.643.2.2.31.13" </td><td>Узел замены алгоритма шифрования, вариант ТК26 1</td></tr>
 * <tr><td>szOID_Gost28147_89_TC26_C_ParamSet</td><td>"1.2.643.2.2.31.14" </td><td>Узел замены алгоритма шифрования, вариант ТК26 3</td></tr>
 * <tr><td>szOID_Gost28147_89_TC26_D_ParamSet</td><td>"1.2.643.2.2.31.15" </td><td>Узел замены алгоритма шифрования, вариант ТК26 4</td></tr>
 * <tr><td>szOID_Gost28147_89_TC26_E_ParamSet</td><td>"1.2.643.2.2.31.16" </td><td>Узел замены алгоритма шифрования, вариант ТК26 5</td></tr>
 * <tr><td>szOID_Gost28147_89_TC26_F_ParamSet</td><td>"1.2.643.2.2.31.17" </td><td>Узел замены алгоритма шифрования, вариант ТК26 6</td></tr>
 * <tr><td>szOID_Gost28147_89_TC26_Z_ParamSet</td><td>"1.2.643.7.1.2.5.1.1" </td><td>Узел замены алгоритма шифрования, вариант ТК26 Z</td></tr>
 * <tr><td>szOID_GostR3410_2001_TestParamSet</td><td>"1.2.643.2.2.35.0"</td><td>Тестовые параметры a, b, p, q, (x,y) алгоритма ГОСТ Р 34.10-2001 </td></tr>
 * <tr><td>szOID_GostR3410_2001_CryptoPro_A_ParamSet</td><td>"1.2.643.2.2.35.1"</td><td>Параметры a, b, p, q, (x,y) цифровой подписи и алгоритма Диффи-Хеллмана на базе алгоритма ГОСТ Р 34.10-2001, вариант криптопровайдера </td></tr>
 * <tr><td>szOID_GostR3410_2001_CryptoPro_B_ParamSet</td><td>"1.2.643.2.2.35.2"</td><td>Параметры a, b, p, q, (x,y) цифровой подписи и алгоритма Диффи-Хеллмана на базе алгоритма ГОСТ Р 34.10-2001, вариант карты КриптоРИК</td></tr>
 * <tr><td>szOID_GostR3410_2001_CryptoPro_C_ParamSet</td><td>"1.2.643.2.2.35.3"</td><td>Параметры a, b, p, q, (x,y) цифровой подписи и алгоритма Диффи-Хеллмана на базе алгоритма ГОСТ Р 34.10-2001, вариант 1</td></tr>
 * <tr><td>szOID_GostR3410_2001_CryptoPro_XchA_ParamSet</td><td>"1.2.643.2.2.36.0"</td><td> Параметры a, b, p, q, (x,y) алгоритма Диффи-Хеллмана на базе алгоритма ГОСТ Р 34.10-2001, вариант криптопровайдера. Используются те же параметры, что и с идентификатором szOID_GostR3410_2001_CryptoPro_A_ParamSet</td></tr>
 * <tr><td>szOID_GostR3410_2001_CryptoPro_XchB_ParamSet</td><td>"1.2.643.2.2.36.1"</td><td>Параметры a, b, p, q, (x,y) цифровой подписи и алгоритма Диффи-Хеллмана на базе алгоритма ГОСТ Р 34.10-2001, вариант 1</td></tr>
 * <tr><td>szOID_tc26_gost_3410_12_256_paramSetA</td><td>"1.2.643.7.1.2.1.1.1"</td><td>Параметры a, b, p, q, (x,y) цифровой подписи и алгоритма Диффи-Хеллмана на базе алгоритма ГОСТ Р 34.10-2012 256 бит, набор A</td></tr>
 * <tr><td>szOID_tc26_gost_3410_12_256_paramSetB</td><td>"1.2.643.7.1.2.1.1.2"</td><td>Параметры a, b, p, q, (x,y) цифровой подписи и алгоритма Диффи-Хеллмана на базе алгоритма ГОСТ Р 34.10-2012 256 бит, набор B</td></tr>
 * <tr><td>szOID_tc26_gost_3410_12_256_paramSetC</td><td>"1.2.643.7.1.2.1.1.3"</td><td>Параметры a, b, p, q, (x,y) цифровой подписи и алгоритма Диффи-Хеллмана на базе алгоритма ГОСТ Р 34.10-2012 256 бит, набор C</td></tr>
 * <tr><td>szOID_tc26_gost_3410_12_256_paramSetD</td><td>"1.2.643.7.1.2.1.1.4"</td><td>Параметры a, b, p, q, (x,y) цифровой подписи и алгоритма Диффи-Хеллмана на базе алгоритма ГОСТ Р 34.10-2012 256 бит, набор D</td></tr>
 * <tr><td>szOID_tc26_gost_3410_12_512_paramSetA</td><td>"1.2.643.7.1.2.1.2.1"</td><td>Параметры a, b, p, q, (x,y) цифровой подписи и алгоритма Диффи-Хеллмана на базе алгоритма ГОСТ Р 34.10-2012 512 бит по умолчанию</td></tr>
 * <tr><td>szOID_tc26_gost_3410_12_512_paramSetB</td><td>"1.2.643.7.1.2.1.2.2"</td><td>Параметры a, b, p, q, (x,y) цифровой подписи и алгоритма Диффи-Хеллмана на базе алгоритма ГОСТ Р 34.10-2012 512 бит, набор B </td></tr>
 * <tr><td>szOID_tc26_gost_3410_12_512_paramSetC</td><td>"1.2.643.7.1.2.1.2.3"</td><td>Параметры a, b, p, q, (x,y) цифровой подписи и алгоритма Диффи-Хеллмана на базе алгоритма ГОСТ Р 34.10-2012 512 бит, набор C </td></tr>
 *</table>
 *
*/

/*! \} */

/*! 
 * \ingroup ProCSPData
 *
 * \brief Блоб с сериализованной псевдоструктурой с расширением.
 *
 * \req_wincryptex
 * \sa CPGetProvParam
 */
typedef struct _CONTAINER_EXTENSION {
    BOOL bCritical; /*!< Флаг критического расширения. */
    DWORD cbExtension; /*!< Длина данных в pbExtension. */
    BYTE pbExtension[1]; /*!< Данные. */
    char sOid[1]; /*!< Строка с OID-ом расширения (невыровненный указатель). */
} CONTAINER_EXTENSION;

//ошибка или недоработка в wincrypt.h
//Use NO_REDIFINE_CERT_FIND_STR to disable redefine
#if defined ( CERT_FIND_SUBJECT_STR ) && !defined ( NO_REDIFINE_CERT_FIND_STR )
#   undef CERT_FIND_SUBJECT_STR
#   undef CERT_FIND_ISSUER_STR
#   ifdef _UNICODE
#	define CERT_FIND_SUBJECT_STR	CERT_FIND_SUBJECT_STR_W
#	define CERT_FIND_ISSUER_STR	CERT_FIND_ISSUER_STR_W
#   else
#	define CERT_FIND_SUBJECT_STR	CERT_FIND_SUBJECT_STR_A
#	define CERT_FIND_ISSUER_STR	CERT_FIND_ISSUER_STR_A
#   endif // !UNICODE
#endif /*defined ( CERT_FIND_SUBJECT_STR ) && !defined ( NO_REDIFINE_CERT_FIND_STR )*/

#if !defined(_DDK_DRIVER_)

typedef struct _CPESS_CERT_ID {
    CRYPT_HASH_BLOB CertHash;
    CERT_ISSUER_SERIAL_NUMBER IssuerSerial;
} CPESS_CERT_ID, *PCPESS_CERT_ID;

typedef struct _CPESS_CERT_IDV2 {
    CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
    CRYPT_HASH_BLOB CertHash;
    CERT_ISSUER_SERIAL_NUMBER IssuerSerial;
} CPESS_CERT_IDV2, *PCPESS_CERT_IDV2,
  CPOTHER_CERT_ID, *PCPOTHER_CERT_ID;

typedef struct _CPCMSG_SIGNING_CERTIFICATE {
    DWORD cCert;
    CPESS_CERT_ID* rgCert;
    DWORD cPolicy;
    CERT_POLICY_INFO* rgPolicy;
} CPCMSG_SIGNING_CERTIFICATE, *PCPCMSG_SIGNING_CERTIFICATE;

typedef struct _CPCMSG_SIGNING_CERTIFICATEV2 {
    DWORD cCert;
    CPESS_CERT_IDV2* rgCert;
    DWORD cPolicy;
    CERT_POLICY_INFO* rgPolicy;
} CPCMSG_SIGNING_CERTIFICATEV2, *PCPCMSG_SIGNING_CERTIFICATEV2;

typedef struct _CPCMSG_OTHER_SIGNING_CERTIFICATE {
    DWORD cCert;
    CPOTHER_CERT_ID* rgCert;
    DWORD cPolicy;
    CERT_POLICY_INFO* rgPolicy;
} CPCMSG_OTHER_SIGNING_CERTIFICATE, *PCPCMSG_OTHER_SIGNING_CERTIFICATE; 

typedef struct _CPCERT_PRIVATEKEY_USAGE_PERIOD {
    FILETIME *pNotBefore;
    FILETIME *pNotAfter;
} CPCERT_PRIVATEKEY_USAGE_PERIOD, *PCPCERT_PRIVATEKEY_USAGE_PERIOD;

typedef struct _GOST_PRIVATE_KEY_TIME_VALIDITY_CONTROL_MODE {
    BOOL useCertificate;
    BOOL useContainer;
} GOST_PRIVATE_KEY_TIME_VALIDITY_CONTROL_MODE, *PGOST_PRIVATE_KEY_TIME_VALIDITY_CONTROL_MODE,
  PRIVATE_KEY_TIME_VALIDITY_CONTROL_MODE, *PPRIVATE_KEY_TIME_VALIDITY_CONTROL_MODE;
/*! \endcond */

#define CPPRIVATEKEY_USAGE_PERIOD_CERT_CHAIN_POLICY_SKIP_END_CERT_FLAG	    (0x00010000)
#define CPTIMESTAMP_SIGNING_CERT_CHAIN_POLICY_IGNORE_NOT_CRITICAL_EKU_FLAG  (0x00020000)
#define CPTIMESTAMP_SIGNING_CERT_CHAIN_POLICY_IGNORE_NOT_ONE_EKU_FLAG	    (0x00040000)

typedef struct _CPPRIVATEKEY_USAGE_PERIOD_EXTRA_CERT_CHAIN_POLICY_PARA {
    DWORD cbSize; 
    FILETIME* pPrivateKeyUsedTime; 
} CPPRIVATEKEY_USAGE_PERIOD_EXTRA_CERT_CHAIN_POLICY_PARA,
*PCPPRIVATEKEY_USAGE_PERIOD_EXTRA_CERT_CHAIN_POLICY_PARA,
CPSIGNATURE_EXTRA_CERT_CHAIN_POLICY_PARA,
*PCPSIGNATURE_EXTRA_CERT_CHAIN_POLICY_PARA,
CPTIMESTAMP_SIGNING_EXTRA_CERT_CHAIN_POLICY_PARA,
*PCPTIMESTAMP_SIGNING_EXTRA_CERT_CHAIN_POLICY_PARA;

#define CPCERT_TRUST_PRIVATE_KEY_IS_NOT_TIME_VALID	    (0x00000001)
#define CPCERT_TRUST_PRIVATE_KEY_IS_NOT_TIME_VALID_FOR_CRL  (0x00000002)
#define CPCERT_TRUST_IS_NOT_CRITICAL_EKU		    (0x00000004)
#define CPCERT_TRUST_IS_NOT_ONE_EKU			    (0x00000008)
#define CPCERT_TRUST_IS_NOT_VALID_FOR_USAGE		    (CERT_TRUST_IS_NOT_VALID_FOR_USAGE)
							 // (0x00000010)
#define CPCERT_TRUST_IS_NOT_VALID_BY_KEYUSAGE		    (0x00000020)
#define CPCERT_TRUST_IS_NOT_VALID_FOR_OCSP_SIGNING	    (0x00000040)

typedef struct _CPPRIVATEKEY_USAGE_PERIOD_EXTRA_CERT_CHAIN_POLICY_STATUS {
    DWORD cbSize; 
    DWORD dwError; 
    LONG lChainIndex; 
    LONG lElementIndex; 
} CPPRIVATEKEY_USAGE_PERIOD_EXTRA_CERT_CHAIN_POLICY_STATUS,
*PCPPRIVATEKEY_USAGE_PERIOD_EXTRA_CERT_CHAIN_POLICY_STATUS,
CPSIGNATURE_EXTRA_CERT_CHAIN_POLICY_STATUS,
*PCPSIGNATURE_EXTRA_CERT_CHAIN_POLICY_STATUS,
CPTIMESTAMP_SIGNING_EXTRA_CERT_CHAIN_POLICY_STATUS,
*PCPTIMESTAMP_SIGNING_EXTRA_CERT_CHAIN_POLICY_STATUS;

typedef struct _CPOCSP_SIGNING_EXTRA_CERT_CHAIN_POLICY_STATUS {
    DWORD cbSize;
    DWORD dwError;
    LONG lChainIndex;
    LONG lElementIndex;
    BOOL fNoCheck;
    BOOL* rgCertIdStatus;
} CPOCSP_SIGNING_EXTRA_CERT_CHAIN_POLICY_STATUS,
*PCPOCSP_SIGNING_EXTRA_CERT_CHAIN_POLICY_STATUS;

#ifndef OCSP_REQUEST_V1

typedef struct _OCSP_CERT_ID {
    CRYPT_ALGORITHM_IDENTIFIER  HashAlgorithm;  // Normally SHA1
    CRYPT_HASH_BLOB             IssuerNameHash; // Hash of encoded name
    CRYPT_HASH_BLOB             IssuerKeyHash;  // Hash of PublicKey bits
    CRYPT_INTEGER_BLOB          SerialNumber;
} OCSP_CERT_ID, *POCSP_CERT_ID;
#define OCSP_REQUEST_V1     0
#endif

typedef BOOL CALLBACK IsOCSPAuthorized_Callback(
    /* [in] */ PCCERT_CONTEXT pOCSPCertContext);

typedef struct _CPOCSP_SIGNING_EXTRA_CERT_CHAIN_POLICY_PARA {
    DWORD cbSize;
    FILETIME* pPrivateKeyUsedTime;
    DWORD cCertId;
    POCSP_CERT_ID rgCertId;
    IsOCSPAuthorized_Callback* pfnIsOCSPAuthorized;
} CPOCSP_SIGNING_EXTRA_CERT_CHAIN_POLICY_PARA,
*PCPOCSP_SIGNING_EXTRA_CERT_CHAIN_POLICY_PARA;

/*! \cond ca  */

/*!
 *  \brief Структура расширения сертификата IssuerSignTool
 *  (средства электронной подписи и УЦ издателя сертификата)
 *
 * \req_wincryptex
 */
typedef struct _CPCERT_ISSUER_SIGN_TOOL {
    LPWSTR pwszSignTool; /*!< Наименование средства электронной подписи издателя. */
    LPWSTR pwszCATool; /*!< Наименование средства УЦ издателя. */
    LPWSTR pwszSignToolCert; /*!< Реквизиты заключения на средство электронной подписи издателя. */
    LPWSTR pwszCAToolCert; /*!< Реквизиты заключения на средство УЦ издателя. */
} CPCERT_ISSUER_SIGN_TOOL, *PCPCERT_ISSUER_SIGN_TOOL;

/*! \endcond */
/*! \cond csp  */

#endif /*!defined(_DDK_DRIVER_)*/

#ifdef __cplusplus
}
#endif // __cplusplus

/*****************************************************
		    CRYPT_PACKET 
******************************************************/
/*! \ingroup ProCSPData
 * \defgroup CryptPacket  Шифрование и хэширование пакета
 *
 * Пакет - неделимый фрагмент данных, подаваемых на функции шифрования 
 * CPEncrypt(), CPCEncrypt(),CPDecrypt(), CPCDecrypt().
 * Пакет состоит из полей:
 * <table><tr><th>
 * Поле 
 * </th><th>
 *      Описание
 * </th></tr><tr><td>
 * Предзаголовок пакета (DIVERSBLOB)
 * </td><td>
 *      Опциональное поле, содержащее блоб диверсификации ключа шифрования и хэширования по алгоритмам CALG_PRO_DIVERS и CALG_PRO12_DIVERS.
 *      Признак обработки поля - установленный флаг CP_CHP_STARTMIX. Поддерживается только при работе с ГОСТ 28147-89.
 * </td></tr><tr><td>
 * Заголовок пакета (HEADER)
 * </td><td>
 *      Опциональное поле длины не более 255 байт. Не шифруется, хэшируется хэш-функцией hHash.
 * </td></tr><tr><td>
 * Вектор инициализации (IV)
 * </td><td>
 *      Опциональное поле, содержащее вектор инициализации шифрования пакета. Не шифруется, хэшируется опционально.
 * </td></tr><tr><td>
 * Тело пакета (PAYLOAD)
 * </td><td>
 *      Обязательное поле, шифруется и хэшируется.
 * </td></tr><tr><td>
 * Трейлер (TRAILER)
 * </td><td>
 *      Опциональное поле длины не более 254 байт. Не шифруется, хэшируется хэш-функцией hHash.
 * </td></tr><tr><td>
 * Значение функции хэширования пакета (HASH)
 * </td><td>
 *      Опциональное поле, может быть зашифровано. 
 * </td></tr>
 * </table> 
 *
 * При шифровании пакетов поддерживаются режимы шифрования: CRYPT_MODE_CNT, CRYPT_MODE_CFB, CRYPT_MODE_CBCSTRICT, CRYPT_MODE_CTR, CRYPT_MODE_MGM.
 * Во всех режимах шифрования может быть использован флаг CRYPT_SIMPLEMIX_MODE.
 * В режимах шифрования CRYPT_MODE_CNT, CRYPT_MODE_CFB, CRYPT_MODE_CBCSTRICT может быть использован флаг CRYPT_PROMIX_MODE.
 * В режиме шифрования CRYPT_MODE_CTR может быть использован флаг CRYPT_ACPKM_MODE.
 *
 * В пакетном режиме шифрования длина пакетов остаётся неизменной.
 *
 * В режиме CBC общая длина шифруемых данных должна быть кратна 8, также должна быть кратной 8 длина 
 * каждого шифруемого элемента IOVEC, в противном случае возвращается ошибка NTE_BAD_DATA. 
 * Пакеты обрабатываются с сохранением размера полей, паддинг в режиме CBC игнорируется.
 *
 * Флаги CP_CHP_IV_RANDOM, CP_CHP_IV_USER, CP_CHP_HASH_PACKET предназначены для обработки 
 * пакетов в потоках с возможным нарушением порядка следования пакетов, с возможной потерей пакетов.
 *
 * Флаги CP_CHP_IV_CHAIN, CP_CHP_HASH_CHAIN, CP_CHP_HASH_NONE  предназначены для обработки пакетов в потоках,
 * гарантирующих доставку всех пакетов в неизменной последовательности.
 * 
 * Во всех режимах объект функции хэширования после завершения обработки пакета 
 * подготовлен для обработки следующего пакета. 
 * При этом, в случае CP_CHP_HASH_CHAIN и CP_CHP_HASH_NONE объект открыт для продолжения хэширования потока, 
 * в случае CP_CHP_HASH_PACKET объект инициализирован.
 *
 * При расшифровании пакета в случае его искажения в канале, приводящего к несовпадению  
 * значения HASH, передаваемого в составе пакета, с вновь рассчитанным значением, функция CPDecrypt() 
 * возвращают ошибку (FALSE), функции CPCDecrypt() и GetLastError() возвращают NTE_BAD_HASH, 
 * объект функции хэширования функциями CPDecrypt(), CPCDecrypt() не инициализируется. 
 * В этом случае приложение может получить рассчитанное значение HASH
 * вызовом CPGetHashParam() и должно принять решение о завершении обрабатываемого потока
 * (например: поток, обрабатываемый с флагом CP_CHP_HASH_CHAIN, должен быть закрыт; 
 * поток, обрабатываемый с флагом CP_CHP_HASH_PACKET может быть продолжен). 
 * В случае продолжения обработки потока приложение должно открыть (создать новый) объект функции хэширования.
 *
 * Во входных параметрах функций шифрования и хэширования пакет может быть представлен как буфером, 
 * определяемым указателем pbData и длиной cbData, так и вектором IOVEC ввода/вывода, 
 * определяемым указателем pbData на вершину массива структур \ref CSP_iovec и числом элементов массива cbData.
 * Режим использования векторной формы представления ввода/вывода определяется флагом CP_CRYPT_DATA_IOVEC, 
 * в настоящей версии СКЗИ режим CP_CRYPT_DATA_IOVEC является подрежимом пакетной обработки.
 *
 * В режиме пакетной обработки возможно получение ключа шифрования и имитозащиты пакета диверсификацией 
 * базовых ключей, ассоциированных с hKey и hHash. Диверсификация осуществляется по алгоритму CALG_PRO_DIVERS/CALG_PRO12_DIVERS 
 * с использованием даных CRYPT_DIVERSBLOB, размещённых в предзаголовке пакета. 
 * Если используется представление данных в форме вектора ввода-вывода, 
 * блоб диверсификации должен передаваться в первой координате вектора целиком.
 * Признаком использования диверсификации ключей является установленный флаг CP_CHP_STARTMIX.
 * Диверсифицированное значение ключей сохраняется для использования для обработки последующих пакетов.
 * Диверсификация ключей не приводит к изменению значений базовых ключей.
 *
 * В режиме пакетной обработки с использованием алгоритма ГОСТ 28147-89 возможна SIMD параллельная обработка до 16 пакетов при использовании 
 * аппаратной платформы, поддерживающей расширения SSSE3, AVX.
 * Все пакеты обрабатываются на ключах  с одним значением для шифрования и 
 * с обним значением для функции хэшироваия.
 * Пакеты должны быть упакованы в массиве структур CSP_Multipacket. 
 * Признаком использования мультипакетной обработки является установленный флаг CP_CHP_MULTIPACKET.
 * Пакеты могут быть представлены как линейным буфером, так и вектором IOVEC ввода/вывода.
 * Требуется, чтобы все пакеты были однотипными, тип пакетов определяется флагом CP_CRYPT_DATA_IOVEC.
 * В мультипакетном режиме использование предварительной диверсификации ключа, 
 * определяемой флагом CP_CHP_STARTMIX, не допускается.
 * См. \ref CryptMultipacket.
 *
 *
 * Флаг CP_CRYPT_NOKEYWLOCK используется для организации шифрования\расшифрования пакетов с использованием алгоритма ГОСТ 28147-89 в
 * многопоточном режиме, при этом ключ шифрования\расшифрования блокируется только на чтение.
 * Для обеспечения данного режима при работе с криптопровайдером уровня ядра ОС необходимо заранее создать специальный объект
 * HCRYPTMODULE с помощью функции CPCGetProvParam() с флагом PP_CREATE_THREAD_CSP; данный объект в дальнейшем
 * следует передавать функциям CPCEncrypt() и CPCDecrypt() в качестве первого параметра.
 *
 * Использование флага CP_CRYPT_NOKEYWLOCK разрешается только совместно с флагом CP_CRYPT_HASH_PACKET, при значении параметра Final == TRUE;
 * использование флага при шифровании\расшифровании на ключе с режимом преобразования (KP_MIXMODE), отличным
 * от CRYPT_SIMPLEMIX_MODE, а также совместно с флагом CP_CHP_IV_CHAIN не допускается.
 *
 * Пример
 * \code
 * CPCGetProvParam(hCSP, hProv, PP_CREATE_THREAD_CSP, NULL, &dwThreadCSPData, 0);
 *
 * pbThreadCSPData = (BYTE*)malloc(dwThreadCSPData);
 *
 * CPCGetProvParam(hCSP, hProv, PP_CREATE_THREAD_CSP, pbThreadCSPData, &dwThreadCSPData, 0);
 *
 * hThreadCSP = (HCRYPTMODULE)pbThreadCSPData;
 *
 * CPCEncrypt(hThreadCSP, hProv, hKey, hHash, TRUE, CP_CHP(CP_CHP_HASH_ENCRYPT | CP_CHP_IV_RANDOM | CP_CHP_STARTMIX |
 * CP_CHP_HASH_PACKET | CP_CRYPT_NOKEYWLOCK, HEADER_BYTE_SIZE, TRAILER_BYTE_SIZE, HASH_DWORD_SIZE), pbThreadPacketData, &cbThreadPacketData, cbThreadPacketData);
 * \endcode
 *
 * Умолчания:
 *
 *   1. В случае hHash=0, значение функции хэширования не рассчитывается.
 *
 *   2.	Представление данных в виде IOVEC является производным от представления, определяемого флагами.
 *      Имеется ввиду, что IOVEC представляет данные, а описание структуры данных содержится во флагах.
 *
 *   3.	Максимальное количество элементов IOVEC зависит от реализации. 
 * Любая реализация должна предоставлять возможность использовать 16 элементов IOVEC.
 *
 *   4. Поле длины элемента IOVEC >= 0.
 *
 *
 * Структура пакета и порядок обработки полей пакета определяются 
 * значениями флагов параметра dwFlags, 
 * объединяемыми операцией OR; значения флагов зависимы, не все 
 * сочетания значений полей допустимы. Для формирования флагов 
 * рекомендуется использовать макрос CP_CHP().
 *
 * \sa #CPEncrypt (CP_CRYPT_HASH_PACKET)
 * \sa #CPDecrypt (CP_CRYPT_HASH_PACKET)
 * \sa #CP_CHP()
 * \{
 */

/*!
 *  \brief Флаг - признак пакетной обработки данных, должен быть установлен, если используется обработка пакета,
 *  в противном случае dwFlags должен быть равен нулю, что соответствует обработке простого потока данных. 
 */
#define CP_CRYPT_HASH_PACKET		(0x80)
/*!
 *  \brief Флаг определяет порядок обработки данных пакета - хэширование (имитозащита), затем шифрование.
 */
#define CP_CHP_HASH_ENCRYPT		(0x00)
/*!
 *  \brief Флаг определяет порядок обработки данных пакета - шифрование, затем хэширование (имитозащита).
 */
#define CP_CHP_ENCRYPT_HASH		(0x10)
/*!
 *  \brief Флаг - признак мультипакетного режима работы. Параметр pbData должен указывать на массив структур 
 *  CSP_MultiPacket_ENC/CSP_Multipacket_DEC, в параметре cbData/reserved передаётся число структур в массиве (не должно превышать 16).
 *  В каждой из структур CSP_MultiPacket_ENC/CSP_Multipacket_DEC до вызова CPEncrypt()/CPDecrypt() соответственно в 
 *  поле dwResult должно быть записано значение 1. В случае ошибок, связанных с проверкой значений имитовставки одного 
 *  или нескольких пакетов (ошибка NTE_BAD_HASH), после выхода из функции в поле dwResult будет 0 только у тех пакетов, 
 *  обработка которых завершилась с успешной проверкой значения имитовставки (значения функции хэширования).
 *  Мультипакетный режим поддерживается только для алгоритма шифрования ГОСТ 28147-89.
 */
#define CP_CHP_MULTIPACKET		(0x20)
/*!
*  \brief Флаг - признак работы с блокировкой ключа только на чтение. 
*    Ситуации, при которой блокировка на чтение невозможна, сопоставляется ошибка NTE_BAD_FLAGS.
*/
#define CP_CRYPT_NOKEYWLOCK		(0x40)
/*!
 *  \brief Флаг хэширования вектора инициализации (IV). Если установлен, IV следует за заголовком пакета и хэшируется. 
 *  Если не установлен, IV, если присутствует в пакете, следует за заголовком пакета, но не хэшируется.
 */
#define CP_CHP_IV_HEADER		(0x08)
/*!
 *  \brief Флаг диверсификации ключа шифрования и хэширования по алгоритму CALG_PRO_DIVERS\CALG_PRO12_DIVERS. 
 *  Если используется представление данных в форме пакета, блоб диверсификации должен передаваться 
 *  в составе пакета в его начале.
 *  Если используется представление данных в форме вектора ввода-вывода, 
 *  блоб диверсификации должен передаваться в первой координате вектора целиком. 
 *  При обработке мультипакета (флаг CP_CHP_MULTIPACKET установлен) блоб диверсификации должен 
 *  передаваться в составе первого пакета, в этом случае все пакеты мультипакета обрабатваются 
 *  на диверсифицированных ключах шифрования и имитозащиты.
 */
#define CP_CHP_STARTMIX			(0x04)
/*!
 *  \brief Маска управления IV. Представляет собой поле из 2 зависимых бит. 
 *  Нулевое значение поля соответствует CP_CHP_IV_CHAIN.
 *  Ненулевые значения соответствуют CP_CHP_IV_USER, CP_CHP_IV_RANDOM.
 *  Может быть установлен только один из флагов CP_CHP_IV_CHAIN, CP_CHP_IV_USER, CP_CHP_IV_RANDOM.
 */
#define CP_CHP_IV_MASK			(0x300) 
/*!
 *  \brief  Если флаг установлен, IV генерируется функцией CPEncrypt(...,CP_CRYPT_HASH_PACKET|CP_CHP_IV_CHAIN...,...) 
 *  (CPCEncrypt()) и передаётся в пакет. Функция CPDecrypt(...,CP_CRYPT_HASH_PACKET|CP_CHP_IV_CHAIN...,...) (CPCEncrypt())
 *  считывает IV из пакета. 
 */
#define CP_CHP_IV_RANDOM		(0x100)
/*!
 *  \brief  Если флаг установлен, приложение устанавливает IV в пакет, 
 *  функции CPEncrypt(...,CP_CRYPT_HASH_PACKET|CP_CHP_IV_CHAIN...,...) (CPCEncrypt()), 
 *  CPDecrypt(...,CP_CRYPT_HASH_PACKET|CP_CHP_IV_CHAIN...,...) (CPCEncrypt()) считывают IV из пакета. 
 */
#define CP_CHP_IV_USER			(0x200)
/*!
 *  \brief  Если флаг установлен, функции CPEncrypt(...,CP_CRYPT_HASH_PACKET|CP_CHP_IV_CHAIN...,...) (CPCEncrypt()), 
 *  CPDecrypt(...,CP_CRYPT_HASH_PACKET|CP_CHP_IV_CHAIN...,...) (CPCDecrypt()) получают IV пакета из контекста ключа.
 */
#define CP_CHP_IV_CHAIN			(0x000)
/*!
 *  \brief Маска управления значением хэш-функции пакета. Представляет собой поле из 2 зависимых бит. 
 *  Нулевое значение поля соответствует CP_CHP_HASH_NONE.
 *  Ненулевые значения соответствуют CP_CHP_HASH_CHAIN, CP_CHP_HASH_PACKET.
 *  Может быть установлен только один из флагов CP_CHP_HASH_NONE, CP_CHP_HASH_CHAIN, CP_CHP_HASH_PACKET.
 */
 #define CP_CHP_HASH_MASK		(0xC00)
/*!
 *  \brief  Если флаг установлен, функция хэширования расчитывается на весь поток пакетов. 
 *  В пакет значение хэш-функции не передаётся.
 */
#define CP_CHP_HASH_NONE		(0x000)
/*!
 *  \brief  Если флаг установлен, функция хэширования рассчитывается на поток пакетов, 
 *  текущее значение хэш-функции устанавливается в пакет функциями 
 *  CPEncrypt(...,CP_CRYPT_HASH_PACKET|CP_CHP_HASH_CHAIN...,...) (CPCEncrypt()).
 *  Функции CPDecrypt(...,CP_CRYPT_HASH_PACKET|CP_CHP_IV_CHAIN...,...) (CPCDecrypt()) сравнивают
 *  рассчитанное значение хэш-функции со значением, полученным из пакета,
 *  и в случае несовпадения возвращают ошибку NTE_BAD_HASH.
 */
#define CP_CHP_HASH_CHAIN		(0x400)
/*!
 *  \brief  Если флаг установлен, функция хэширования рассчитывается на пакет, 
 *  значение хэш-функции устанавливается в пакет функциями 
 *  CPEncrypt(...,CP_CRYPT_HASH_PACKET|CP_CHP_HASH_CHAIN...,...) (CPCEncrypt()).
 *  Функции CPDecrypt(...,CP_CRYPT_HASH_PACKET|CP_CHP_IV_CHAIN...,...) (CPCDecrypt()) сравнивают
 *  рассчитанное значение хэш-функции со значением, полученным из пакета,
 *  и в случае несовпадения возвращают ошибку NTE_BAD_HASH.
 */
#define CP_CHP_HASH_PACKET		(0x800)
/*!
 *  \brief Маска размера значения хэш-функции в двойных словах (4 октета), устанавливаемого в пакет.
 *  Возможные значения: 1 (для имитозащиты) от 1 до 8 (для хэш-функций и HMAC).
 */
#define CP_CHP_HASH_SIZE_MASK		(0xF000)
/*!
 *  \brief Маска размера трейлера в байтах, значения 0 - 254 означают длину трейлера, 
 *  значение  255 означает: длина трейлера 0, значения хэш-функции в пакете шифруется.
 */
#define CP_CHP_TRAILER_MASK		(0xFF0000)
/*!
 *  \brief Флаг, указывающий на шифрование хэш-значения.
 */
#define CP_CHP_ENCRYPTED_TRAILER	(CP_CHP_TRAILER_MASK>>CP_CHP_TRAILER_SHIFT)

/*!
 *  \brief Маска размера заголовка в байтах, размер может проинимать значения 0 - 255. 
 */
#define CP_CHP_HEADER_MASK		(0xFF000000)

 /*!
 *  \brief Пакетные флаги для AEAD-режимов
 */
#define BASE_AEAD_FLAGS	    (CP_CHP_IV_CHAIN | CP_CHP_HASH_PACKET)

/*! \brief Макрос для формирования параметра dwFlags (флагов) функций
 *  CPEncrypt() и CPDecrypt()
 *
 *  Флаги (dwFlags) формируются на основе параметров пакета:
 *  - флагов порядка вычисления хэш-функции и выработки синхропосылки;
 *  - размера заголовка;
 *  - размера "хвоста";
 *  - размера значения хэш-функции.
 */
#define CP_CHP(Flags,HeaderByteSize,TrailerByteSize,HashDWordSize) (\
            (Flags)|CP_CRYPT_HASH_PACKET|\
            (((HeaderByteSize)<<CP_CHP_HEADER_SHIFT)&CP_CHP_HEADER_MASK)|\
            (((TrailerByteSize)<<CP_CHP_TRAILER_SHIFT)&CP_CHP_TRAILER_MASK)|\
            (((HashDWordSize)<<CP_CHP_HASH_SIZE_SHIFT)&CP_CHP_HASH_SIZE_MASK)\
        )
/*! \} */

 /*!
 *  \brief Флаг - признак пакета, содержащего запись протокола TLS.
 *   При использовании этого флага будет производиться работа с заголовком пакета в соответствии
 *   с подпротоколом RECORD протокола TLS.
 */
#define CP_CHP_TLS_PACKET		(0x01)

 /*internal
  *  \brief Сумма указателя со смещением.
  *      p - указатель
  *      w - смещение
  */
#define _CP_CHP_ADD_(p,w) \
	    ((void *)(((char *)p) + (w)))
#define _CP_CHP_SUB_(p,w) \
	    ((void *)(((char *)p) - (w)))


  /*internal
   *  \brief Проверка границ буфера.
   *	d - указатель на буфер
   *      l - длина буфера
   *      p - результирующий указатель на поле пакета
   *      w - длина поля
   */
#define _CP_CHP_SAFE_CHECK_(d,l,p,w)					\
	    (NULL != (d) && (size_t)(w) <= (size_t)(l) &&		\
	     (void *)(d) <= (void *)(p) &&					\
	     _CP_CHP_ADD_((p),(w)) <= _CP_CHP_ADD_((d),(l))		\
		? (p)							\
		: NULL							\
	    )

/*! \ingroup ProCSPData
 * \defgroup PacketMacros Вспомогательные макросы описания структуры пакета
 *
 *  В макросах приняты обозначения параметров:
 *  - параметр f сответствует dwFlags;
 *  - параметр d сответствует указателю на буфер, содержащий пакет;
 *  - параметр l сответствует длине пакета.
 *
 * \{
 */

/*!
 *  \brief Сдвиг поля для маски CP_CHP_HASH_SIZE_MASK. 
 */
#define CP_CHP_HASH_SIZE_SHIFT		(12)
/*!
 *  \brief Сдвиг поля для маски CP_CHP_TRAILER_MASK. 
 */
#define CP_CHP_TRAILER_SHIFT		(16)
/*!
 *  \brief Сдвиг поля для маски CP_CHP_HEADER_MASK. 
 */
#define CP_CHP_HEADER_SHIFT		(24)
/* 
    Aplication Packet (A-Packet, А-пакет)
    Структура Ф-пакета
    IV
    IV присутствует в А-пакете только тогда, когда он необходим для шифрования,
    т.е. IV типа RANDOM или USER присутствуют в А-пакете.
    Если CP_CHP_IV_HEADER установлен, IV входит в состав хидера и только в этом случае IV хэшируется.
    Если CP_CHP_IV_HEADER не установлен, IV не входит в состав хидера и должен присутствовать в А-пакете.
    IV типа RANDOM устанавливается в А-пакет и считывается из него функциями Encrypt()/Decrypt().
    IV типа USER устанавливается в А-пакет приложением, считывается из него функциями Encrypt()/Decrypt().
    IV типа CHAIN устанавливается приложением на ключ функцией SetKeyParam(...,KP_IV,...), 
    в А-пакет IV типа CHAIN не входит.

*/
/*!
 *  \brief Размер поля IV для алгоритма ГОСТ 28147-89 в пакете. 
 */
#define CP_CHP_IV_SIZE(f) (((f)&CP_CHP_IV_MASK)?(SEANCE_VECTOR_LEN):(0))

/*!
*  \brief Размер поля IV переменной длины в пакете.
*/
#define CP_CHP_IV_BLOB_SIZE(f, ivlen) (((f)&CP_CHP_IV_MASK)?(ivlen):(0))
/*!
 *  \brief Указатель на поле IV для алгоритма ГОСТ 28147-89 в пакете. 
 */
#define CP_CHP_IV_DATA(f,d,l) _CP_CHP_SAFE_CHECK_((d),(l),		\
		_CP_CHP_ADD_((d),					\
		    (((f)&CP_CHP_HEADER_MASK)>>CP_CHP_HEADER_SHIFT)),	\
		CP_CHP_IV_BLOB_SIZE(f, SEANCE_VECTOR_LEN)					\
	    )

/*!
 *  \brief Указатель на поле IV переменной длины в пакете
 */
#define CP_CHP_IV_BLOB_DATA(f,d,l,ivlen) _CP_CHP_SAFE_CHECK_((d),(l),		\
		_CP_CHP_ADD_((d),					\
		    (((f)&CP_CHP_HEADER_MASK)>>CP_CHP_HEADER_SHIFT)),	\
		CP_CHP_IV_BLOB_SIZE(f,ivlen)					\
	    )

/*  
    HEADER
    В размер хидера включён IV и хэшируются хидер и IV.
    Таким образом всегда выполняется 
    HashData(...,CP_CHP_HEADER_DATA(dwFlags,pbData,dwDataLen),CP_CHP_HEADER_SIZE(dwFlags));
*/
/*!
 *  \brief Указатель на поле заголовка в пакете, если заголовок присутствует. 
 */
#define CP_CHP_HEADER_DATA(f,d,l) _CP_CHP_SAFE_CHECK_((d),(l),		\
					(d), CP_CHP_PUREHEADER_SIZE(f))
/*!
 *  \brief Размер поля заголовка пакета (исключая IV). 
 */
#define CP_CHP_PUREHEADER_SIZE(f)					\
			(((f)&CP_CHP_HEADER_MASK)>>CP_CHP_HEADER_SHIFT)
/*!
 *  \brief Размер хэшируемого поля заголовка пакета и поля IV (если IV хэшируется). 
 */
#define CP_CHP_HEADER_SIZE_INT(f,ivlen)	(CP_CHP_PUREHEADER_SIZE(f) +	\
					(((f)&CP_CHP_IV_HEADER)		\
					? CP_CHP_IV_BLOB_SIZE(f, ivlen)	\
					: 0))

 /*!
  *  \brief Размер хэшируемого поля заголовка пакета и поля IV (если IV хэшируется) для алгоритма ГОСТ 28147-89.
  */
#define CP_CHP_HEADER_SIZE(f) CP_CHP_HEADER_SIZE_INT(f, SEANCE_VECTOR_LEN) 

/*!
 *  \brief Суммарный размер поля заголовка пакета и поля IV. 
 */
#define CP_CHP_REALHEADER_SIZE_INT(f, ivlen)   (CP_CHP_PUREHEADER_SIZE(f) +		\
					CP_CHP_IV_BLOB_SIZE(f, ivlen))

 /*!
  *  \brief Суммарный размер поля заголовка пакета и поля IV для алгоритма ГОСТ 28147-89.
  */
#define CP_CHP_REALHEADER_SIZE(f) CP_CHP_REALHEADER_SIZE_INT(f, SEANCE_VECTOR_LEN)
/*  
    HASH
    Значение Хэша присутствует в А-пакете только для типов CHAIN и PACKET.
    Для хэша типа PACKET либо CHAIN функция Encrypt() вычисляет и устанавливает значение хэша в пакет, 
    функция Decrypt() вычисляет значение хэша и сравнивает его со значением из пакета, 
    в случае несовпадения возвращается ошибка NTE_BAD_HASH (CRYPT_E_HASH_VALUE). 
    Приложение само может получить значение хэша на приёме вызовом функции GetHashParam(...,HP_HASHVAL,...).
    Хэш типа NONE обрабатывается приложением, его значение в А-пакетне помещается.
    Значение хэша будет зашифрованно, если поле CP_CHP_TRAILER_MASK установлено в 0xff.
*/

/*!
 *  \brief Размер поля значения хэш-функции. 
 */
#define CP_CHP_HASH_SIZE(f)						\
		(sizeof(DWORD)*						\
		    (((f)&CP_CHP_HASH_MASK)				\
		    ?((f&CP_CHP_HASH_SIZE_MASK)>>CP_CHP_HASH_SIZE_SHIFT)\
		    :0))
/*!
 *  \brief Указатель на поле значения хэш-функции в пакете, если поле присутствует. 
 */
#define CP_CHP_HASH_DATA(f,d,l)	_CP_CHP_SAFE_CHECK_((d),(l),		\
		_CP_CHP_ADD_((d), (l)-CP_CHP_HASH_SIZE(f)),		\
		CP_CHP_HASH_SIZE(f)					\
	    )

/*!
 *  \brief Длина хэшируемого поля пакета(в случае, когда поле IV хэшируется). 
 */
#define CP_CHP_HASH_LEN(f,l) (l-CP_CHP_HASH_SIZE(f))
/*!
 *  \brief Длина первого хэшируемого поля (в случае, когда поле IV не хэшируется). 
 */
#define CP_CHP_HASH_LEN_1(f)  CP_CHP_PUREHEADER_SIZE(f)


/*!
 *  \brief Размер поля трейлера. 
 */
#define CP_CHP_TRAILER_SIZE(f)						\
		    ((((f)&CP_CHP_TRAILER_MASK)==CP_CHP_TRAILER_MASK)	\
		    ?(0)						\
		    :(((f)&CP_CHP_TRAILER_MASK)>>CP_CHP_TRAILER_SHIFT))	\
/*!
 *  \brief Указатель на поле трейлера в пакете, если поле присутствует. 
 */
#define CP_CHP_TRAILER_DATA(f,d,l)  _CP_CHP_SAFE_CHECK_((d),(l),	\
		_CP_CHP_SUB_(CP_CHP_HASH_DATA((f),(d),(l)),		\
					CP_CHP_TRAILER_SIZE(f)),	\
		CP_CHP_TRAILER_SIZE(f)					\
	    )

/*!
 *  \brief Размер тела пакета. 
 */
#define CP_CHP_PAYLOAD_SIZE_INT(f,l,ivlen) ((l) -			\
				    CP_CHP_REALHEADER_SIZE_INT(f,ivlen) -	\
				    CP_CHP_TRAILER_SIZE(f) -		\
				    CP_CHP_HASH_SIZE(f))

 /*!
  *  \brief Размер тела пакета для алгоритма ГОСТ 28147-89.
  */
#define CP_CHP_PAYLOAD_SIZE(f,l) CP_CHP_PAYLOAD_SIZE_INT(f,l,SEANCE_VECTOR_LEN)

/*!
 *  \brief Размер шифруемого поля пакета. 
 */
#define CP_CHP_CIPHER_SIZE_INT(f,l,ivlen) (					\
		(l) -							\
		CP_CHP_REALHEADER_SIZE_INT(f,ivlen) -				\
		CP_CHP_TRAILER_SIZE(f) -				\
		((((f)&CP_CHP_TRAILER_MASK)==CP_CHP_TRAILER_MASK)	\
		    ?(0)						\
		    :(CP_CHP_HASH_SIZE(f)))				\
	    )

 /*!
  *  \brief Размер шифруемого поля пакета для алгоритма ГОСТ 28147-89.
  */
#define CP_CHP_CIPHER_SIZE(f,l) CP_CHP_CIPHER_SIZE_INT(f,l,SEANCE_VECTOR_LEN)
/*!
 *  \brief Указатель на шифруемое поле пакета. 
 */
#define CP_CHP_CIPHER_DATA_INT(f,d,l,ivlen)   _CP_CHP_SAFE_CHECK_((d),(l),	\
		_CP_CHP_ADD_((d), CP_CHP_REALHEADER_SIZE_INT(f,ivlen)),		\
		CP_CHP_CIPHER_SIZE_INT(f,l,ivlen)					\
	    )
 /*!
  *  \brief Указатель на шифруемое поле пакета для алгоритма ГОСТ 28147-89.
  */
#define CP_CHP_CIPHER_DATA(f,d,l)  CP_CHP_CIPHER_DATA_INT(f,d,l,SEANCE_VECTOR_LEN)

/*!
 *  \brief Указатель на второе хэшируемое поле пакета (в случае, когда поле IV не хэшируется). 
 */
#define CP_CHP_HASH_DATA_2_INT(f,d,l,ivlen)   CP_CHP_CIPHER_DATA_INT((f),(d),(l),(ivlen))

 /*!
  *  \brief Указатель на второе хэшируемое поле пакета (в случае, когда поле IV не хэшируется) для алгоритма ГОСТ 28147-89.
  */
#define CP_CHP_HASH_DATA_2(f,d,l)   CP_CHP_HASH_DATA_2_INT((f),(d),(l),SEANCE_VECTOR_LEN)

/*!
 *  \brief Длина второго хэшируемого поля пакета (в случае, когда поле IV не хэшируется). 
 */
#define CP_CHP_HASH_LEN_2_INT(f,l,ivlen)  (					\
		CP_CHP_CIPHER_SIZE_INT(f,l,ivlen) + CP_CHP_TRAILER_SIZE(f) -	\
		((((f)&CP_CHP_TRAILER_MASK)==CP_CHP_TRAILER_MASK)	\
		    ?(CP_CHP_HASH_SIZE(f))				\
		    :(0))						\
	    )

 /*!
  *  \brief Длина второго хэшируемого поля пакета (в случае, когда поле IV не хэшируется) для алгоритма ГОСТ 28147-89.
  */
#define CP_CHP_HASH_LEN_2(f,l) CP_CHP_HASH_LEN_2_INT(f,l,SEANCE_VECTOR_LEN)
/*! \} */

/*! \ingroup ProCSPData
 * \defgroup CryptIOvec  Вектор ввода вывода
 *
 * Если при вызове функций шифрования CPEncrypt(),
 * CPCEncrypt(), CPDecrypt() или CPCDecrypt() в параметре dwFlags
 * установлены флаги CP_CRYPT_HASH_PACKET и  CP_CRYPT_DATA_IOVEC,
 * или при вызове функций хэширования CPHashData() и CPCHashData()
 * установлен флаг CP_HASH_DATA_IOVEC, то
 * обрабатываемые данные представлены в форме вектора ввода-вывода --
 * массивом структур #CSP_iovec.
 * Последовательность структур в массиве должна соответствовать
 * последовательности фрагментов данных в пакете.
 */

#if !defined(UNIX)
    ///*
    // * WinSock 2 extension -- WSABUF and QOS struct, include qos.h
    // * to pull in FLOWSPEC and related definitions
    // */
    //
    //typedef struct _WSABUF {
    //    u_long      len;     /* the length of the buffer */
    //    char FAR *  buf;     /* the pointer to the buffer */
    //} WSABUF, FAR * LPWSABUF;
    //
    //Проект транспорта в IDL (из C:\WINDDK\6001.18001\inc\api\ws2def.h)
    //typedef struct _WSABUF {
    //	ULONG len;     /* the length of the buffer */
    //	__field_bcount(len) CHAR FAR *buf; /* the pointer to the buffer */
    //} WSABUF, FAR * LPWSABUF;
    
    #ifndef RPC_CSP_iovec
    #define RPC_CSP_iovec

	//typedef struct _WSABUF {
	//	ULONG len;     /* the length of the buffer */
	//	[size_is (len)] CHAR FAR *buf; /* the pointer to the buffer */
	//} WSABUF, FAR * LPWSABUF;

	typedef CHAR *CSPiov_ptr_type;
	typedef ULONG CSPiov_len_type;

		// TODO: Ещё раз проверить, быть может, можно всегда 
		// использовать системные стуктуры
	    /*! \ingroup CryptIOvec
	    *
	    * \brief Cтруктура определяет представление фрагмента данных 
	    *	      во внешнем интерфейсе.
	    *
	    * \note На уровне приложений пользователя во всех Windows CSP_iovec 
	    * является макросом для WSABUF, 
	    * поэтому для использования CSP_iovec требуется 
	    * "#include <Winsock2.h>".
	    *
	    * \note На уровне приложений пользователя в POSIX 
	    * (Linux/Solaris/AIX/FreeBSD) системах CSP_iovec является макросом 
	    * для struct iovec, поэтому для использования CSP_iovec требуется 
	    * "#include <sys/uio.h>".
	    */
	    typedef struct CSP_iovec_ {
		CSPiov_len_type CSPiov_len; /*!< Длина фрагмента данных в байтах. */
		CSPiov_ptr_type CSPiov_ptr; /*!< Указатель на фрагмент данных. */
	    } CSP_iovec;
	#if !defined(CSP_LITE)
		// На уровне приложений используем структуру ОС
		// Однако, представляется желательным, совпадение 
		// представлений стуктур ядра и пользователя
	    #define CSP_iovec	    WSABUF
	    #define CSPiov_len	    len
	    #define CSPiov_ptr	    buf
	#endif 

	/*! \ingroup CryptIOvec
	 *
	 * \brief Максимально допустимое число фрагментов в 
	 *        представлении пакета вектором ввода вывода.
	 * 
	 */
	#define CSP_UIO_MAXIOV 		(1024-16)

	/*! \ingroup CryptIOvec
	 *
	 * \brief Максимально допустимое число фрагментов при 
	 *        использовании библиотеки уровня ядра или в 
	 *        адресном пространстве пользователя.
	 * 
	 */
    	#define CSP_KERNEL_UIO_MAXIOV	(1024-16)

    #endif /* RPC_CSP_iovec */
#else
    // Gnu lib
    //   #define UIO_MAXIOV      1024
    //                                                                               
    //   /* Structure for scatter/gather I/O.  */
    //   struct iovec
    //     {
    //        void *iov_base;     /* Pointer to data.  */
    //        size_t iov_len;     /* Length of data.  */                                    };
    //     };

    #if defined(SOLARIS) && !defined(_XPG4_2) && !defined(CSP_LITE)
        #include <sys/types.h>
    	typedef caddr_t CSPiov_ptr_type;
	#if defined(_LP64)
	    typedef size_t CSPiov_len_type;
	#else
	    typedef long CSPiov_len_type;
	#endif
    #else
	typedef void* CSPiov_ptr_type;
	typedef size_t CSPiov_len_type;
    #endif

	    // TODO: Ещё раз проверить, быть может, можно всегда 
	    // использовать системные стуктуры
	typedef struct CSP_iovec_ {
	    CSPiov_ptr_type CSPiov_ptr; /*!<Указатель на фрагмент данных.*/
	    CSPiov_len_type CSPiov_len; /*!<Длина фрагмента данных в байтах.*/
	} CSP_iovec;
    #if !defined(CSP_LITE)
	    // На уровне приложений используем структуру ОС для 
	    // упрощения взаимодействия с подсистемой В/В ОС.
	    // Однако, представляется желательным, совпадение 
	    // представлений стуктур ядра и пользователя для целей
	    // более адекватного тестирования "ядерного" кода в режиме пользователя.
	#define CSP_iovec	    struct iovec
	#define CSPiov_ptr	    iov_base
	#define CSPiov_len	    iov_len
    #endif 
#ifdef ANDROID
#	define IOV_MAX 16
#endif

    #define CSP_UIO_MAXIOV 		(IOV_MAX-2)
    #define CSP_KERNEL_UIO_MAXIOV	(1024-16)
#endif

/*! \ingroup CryptIOvec
 *
 * \brief Значение не инициализированного поля длины.
 * 
 */
#define CSP_UIOV_MAXBAD_LEN ((CSPiov_len_type)0x7fffFFFF)

/*! \ingroup CryptIOvec
 *
 * \brief Макрос возвращает указатель на фрагмент данных с номером n в векторе ввода вывода.
 *
 * Параметры:
 * - p - указатель на первый элемент в массиве структур CSP_iovec;
 * - n - номер структуры в векторе ввода вывода.
 */
#define IOVEC_PTR(p,n) (((CSP_iovec*)p)[n].CSPiov_ptr)
/*! \ingroup CryptIOvec
 *
 * \brief Макрос возвращает длину фрагмента данных с номером n в векторе ввода вывода.
 *
 * Параметры:
 * - p - указатель на первый элемент в массиве структур CSP_iovec;
 * - n - номер структуры в векторе ввода вывода.
 */
#define IOVEC_LEN(p,n) (((CSP_iovec*)p)[n].CSPiov_len)
/*! \ingroup CryptIOvec
 *
 *  \brief Флаг - признак представления пакета в форме вектора ввода/вывода. 
 *  Для функций CPEncrypt(), CPCEncrypt(),CPDecrypt(), CPCDecrypt() флаг
 *  должен быть установлен, если используется представление пакета в форме вектора ввода/вывода,
 *  в противном случае пакет представляется буфером. См. \ref CryptPacket
 */
#define CP_CRYPT_DATA_IOVEC		(0x2)
/*! \ingroup CryptIOvec
 *
 *  \brief Флаг параметра dwFlags - признак представления данных в форме вектора ввода/вывода 
 *  для функций CPHashData() и CPCHashData(). Должен быть установлен, если используется 
 *  представление данных в форме вектора ввода/вывода, в противном случае данные представляются буфером. 
 */
#define CP_HASH_DATA_IOVEC		CP_CRYPT_DATA_IOVEC

#define CP_CRYPT_SET_TESTER_STATUS	(0x2)
#define CP_CRYPT_SELFTEST_FORCE_FAIL 	(0x4)
#define CP_CRYPT_SELFTEST_FORCE_SUCCESS	(0x8)

#define CP_CRYPT_SELFTEST_THROW		(0x100000)
#if defined IGNORE_CPCSP_6005
#define CP_CRYPT_SELFTEST_REAL_THROW	(0x200000)
#endif	/* IGNORE_CPCSP_6005 */
#define CP_CRYPT_SELFTEST_THROW_SHIFT	(8)
#define CP_CRYPT_SELFTEST_THROW_MASK	(0x00FF00)
#define CP_CRYPT_SELFTEST_THROW_ILL	(0x000400)
#define CP_CRYPT_SELFTEST_THROW_TRAP	(0x000500)
#define CP_CRYPT_SELFTEST_THROW_ABRT	(0x000600)
#define CP_CRYPT_SELFTEST_THROW_FPE	(0x000800)
#define CP_CRYPT_SELFTEST_THROW_BUS	(0x000A00)
#define CP_CRYPT_SELFTEST_THROW_SEGV	(0x000B00)
#define CP_CRYPT_SELFTEST_THROW_SYS	(0x000C00)
#define CP_CRYPT_SELFTEST_THROW_USR1	(0x001E00)

#define CP_REUSABLE_HMAC		(0x4)
#define CP_MULTI_HASH_FLAG		(0x8)
#define CP_IMIT_NO_KEY_LOAD             (0x10)
#define CP_HASH_ITER_NUMBER		(0x20)
#define CP_VERIFY_HMAC_FOR_SIGN		(0x40)
#define	CP_VERIFY_SIGN_FOR_SIGN		(0x80)

#define MIN_MULTI_HASH_COUNT		(0x01)
#define MAX_MULTI_HASH_COUNT		(0x40)

#define CP_CRYPT_GETUPPERKEY		(0x200)

#define CP_CRYPT_DUPLICATE_KEY		(0x20)

/*! \ingroup ProCSPData
 * \defgroup CryptMultipacket  Мультипакетная обработка 
 * Функции CPEncrypt(), CPCEncrypt(),CPDecrypt(), CPCDecrypt()
 * допускают мультипакетную обработку по технологии SIMD при использовании 
 * аппаратной платформы, поддерживающей расширения SSSE3, AVX.
 * Поддерживается только шифрование по ГОСТ 28147-89.
 */

/*! \ingroup CryptMultipacket
 *  \brief Используется только для совместимости; заменена CSP_Multipacket_ENC и CSP_Multipacket_DEC.
 *  
 */
typedef struct CSP_Multipacket_ {
    BYTE*	    pbData;	/*!< указатель на линейный пакет, указатель на IOVEC. */
    DWORD	    cbData;	/*!< длина линейного пакета; общая длина элементов IOVEC (при расшифровании - число элементов IOVEC). */
    DWORD	    dwBufLen;	/*!< длина буфера линейного пакета, число элементов IOVEC (при расшифровании поле не используется). */
    DWORD	    dwResult;	/*!< результат обработки пакета.  */
} CSP_Multipacket;

/*! \ingroup CryptMultipacket
*  \brief Структура для передачи параметров для шифрования в случае мультипакетной обработки
* (использования флага CP_CHP_MULTIPACKET). Мультипакет передаётся массивом структур CSP_Multipacket_ENC.
* Каждая структура передаёт пакет как линейный буфер, либо как IOVEC, если в
* параметре dwFlags установлены флаги CP_CRYPT_HASH_PACKET, CP_CHP_MULTIPACKET и
* CP_CRYPT_DATA_IOVEC.
*
*/
typedef  struct CSP_Multipacket_ENC_ {
	BYTE*	    pbEncData; /*!< указатель на линейный пакет, указатель на IOVEC. */
	DWORD	    cbEncDataLen; /*!< длина линейного пакета; общая длина элементов IOVEC */
	DWORD	    dwEncBufLen; /*!< длина буфера линейного пакета, число элементов IOVEC */
	DWORD	    dwEncResult; /*!< результат обработки пакета.  */
} CSP_Multipacket_ENC;


/*! \ingroup CryptMultipacket
*  \brief Структура для передачи параметров для расшифрования в случае мультипакетной обработки
* (использования флага CP_CHP_MULTIPACKET). Мультипакет передаётся массивом структур CSP_Multipacket_DEC.
* Каждая структура передаёт пакет как линейный буфер, либо как IOVEC, если в
* параметре dwFlags установлены флаги CP_CRYPT_HASH_PACKET, CP_CHP_MULTIPACKET и
* CP_CRYPT_DATA_IOVEC.
*
*/
typedef  struct CSP_Multipacket_DEC_ {
	BYTE*	    pbDecData; /*!< указатель на линейный пакет, указатель на IOVEC. */
	DWORD	    dwDecDataLen; /*!< длина линейного пакета, число элементов IOVEC */
	DWORD	    reserved; /*!< длина буфера линейного пакета, число элементов IOVEC */
	DWORD	    dwDecResult; /*!< результат обработки пакета.  */
} CSP_Multipacket_DEC;

#define MultiPacket_PTR(p,n) (((CSP_Multipacket*)p)[n].pbData)

/*! \ingroup CryptMultipacket
* \brief Макрос возвращает указатель на шифруемый пакет с номером n в массиве пакетов.
*
* Параметры:
* - p - указатель на первый элемент в массиве структур CSP_Multipacket_ENC;
* - n - номер структуры в массиве пакетов.
*/
#define MultiPacket_ENC_PTR(p,n) (((CSP_Multipacket_ENC*)p)[n].pbEncData)
/*! \ingroup CryptMultipacket
* \brief Макрос возвращает указатель на расшифровываемый пакет с номером n в массиве пакетов.
*
* Параметры:
* - p - указатель на первый элемент в массиве структур CSP_Multipacket_DEC;
* - n - номер структуры в массиве пакетов.
*/
#define MultiPacket_DEC_PTR(p,n) (((CSP_Multipacket_DEC*)p)[n].pbDecData)


#define MultiPacket_LEN(p,n) (((CSP_Multipacket*)p)[n].cbData)

/*! \ingroup CryptMultipacket
* \brief Макрос возвращает длину шифруемого пакета с номером n в массиве пакетов 
* либо общую длину в представлении шифруемого пакета вектором ввода-вывода
*
* Параметры:
* - p - указатель на первый элемент в массиве структур CSP_Multipacket_ENC;
* - n - номер структуры в массиве пакетов.
*/
#define MultiPacket_ENC_LEN(p,n) (((CSP_Multipacket_ENC*)p)[n].cbEncDataLen)

/*! \ingroup CryptMultipacket
* \brief Макрос возвращает длину расшифровываемого пакета с номером n в массиве пакетов либо число элементов вектора ввода-вывода.
*
* Параметры:
* - p - указатель на первый элемент в массиве структур CSP_Multipacket_DEC;
* - n - номер структуры в массиве пакетов.
*/
#define MultiPacket_DEC_LEN(p,n) (((CSP_Multipacket_DEC*)p)[n].dwDecDataLen)

#define MultiPacket_BUFLEN(p,n) (((CSP_Multipacket*)p)[n].dwBufLen)

/*! \ingroup CryptMultipacket
* \brief Макрос возвращает длину буфера шифруемого линейного пакета с номером n в массиве пакетов либо число элементов вектора ввода-вывода.
*
* Параметры:
* - p - указатель на первый элемент в массиве структур CSP_Multipacket_ENC;
* - n - номер структуры в массиве пакетов.
*/
#define MultiPacket_ENC_BUFLEN(p,n) (((CSP_Multipacket_ENC*)p)[n].dwEncBufLen)

#define MultiPacket_RES(p,n) (((CSP_Multipacket*)p)[n].dwResult)

/*! \ingroup CryptMultipacket
* \brief Макрос возвращает результат обработки пакета с номером n в массиве пакетов.
* Для функций CPEncrypt(), CPCEncrypt()
* перед их вызовом в это поле устанавливается единица.
* Параметры:
* - p - указатель на первый элемент в массиве структур CSP_Multipacket_ENC;
* - n - номер структуры в массиве пакетов.
*/
#define MultiPacket_ENC_RES(p,n) (((CSP_Multipacket_ENC*)p)[n].dwEncResult)

/*! \ingroup CryptMultipacket
* \brief Макрос возвращает результат обработки пакета с номером n в массиве пакетов.
* Для функций CPDecrypt(), CPCDecrypt()
* перед их вызовом в это поле устанавливается единица.
* После вызова функций CPDecrypt(), CPCDecrypt() значение ноль в
* данном поле свидетельствует, что пакет с номером n обработан корректно,
* значение хэш функции пакета совпало с вычисленным значением;
* значение единица в данном поле свидетельствует о том, что значения хэш функций не совпали.
* Параметры:
* - p - указатель на первый элемент в массиве структур CSP_Multipacket_DEC;
* - n - номер структуры в массиве пакетов.
*/
#define MultiPacket_DEC_RES(p,n) (((CSP_Multipacket_DEC*)p)[n].dwDecResult)

// Макросы для неименованных union

#ifdef UNIX
#define UNNAMED_UNION_A f_name.
#else
#define UNNAMED_UNION_A
#endif

#ifdef UNIX
#define UNNAMED_UNION_B _empty_union_.
#else
#define UNNAMED_UNION_B
#endif

// Константы, используемые в CertEnumPhysicalStore при добавлении хранилищ ОС к
// Capilite-хранилищам. Аналогичны CERT_PHYSICAL_STORE_DEFAULT_NAME и сходным константам.
#define CERT_PHYSICAL_STORE_WINDOWS_NAME L".Windows"
#define CERT_PHYSICAL_STORE_MACOS_NAME L".macOS"

// CERT_CHAIN_ENGINE_CONFIG с полями, добавленными в Windows 7 и 8:
// hExclusiveRoot, hExclusiveTrustedPeople, dwExclusiveFlags
typedef struct _CERT_CHAIN_ENGINE_CONFIG_WIN8 {
    DWORD       cbSize;
    HCERTSTORE  hRestrictedRoot;
    HCERTSTORE  hRestrictedTrust;
    HCERTSTORE  hRestrictedOther;
    DWORD       cAdditionalStore;
    HCERTSTORE* rghAdditionalStore;
    DWORD       dwFlags;
    DWORD       dwUrlRetrievalTimeout;      // milliseconds
    DWORD       MaximumCachedCertificates;
    DWORD       CycleDetectionModulus;
    HCERTSTORE  hExclusiveRoot;
    HCERTSTORE  hExclusiveTrustedPeople;
    DWORD       dwExclusiveFlags;
} CERT_CHAIN_ENGINE_CONFIG_WIN8, *PCERT_CHAIN_ENGINE_CONFIG_WIN8;

// колбэки для CertVerifyCertificateChainPolicy
typedef BOOL (WINAPI VerifyChainPolicyCallback_t)(
    LPCSTR pszPolicyOID,
    PCCERT_CHAIN_CONTEXT pChainContext,
    PCERT_CHAIN_POLICY_PARA pPolicyPara,
    PCERT_CHAIN_POLICY_STATUS pPolicyStatus);

// колбэки для CryptRetrieveObjectByUrlA
#define CP_OID_RETRIEVE_OBJECT_BY_URL_A_FUNC "CpDllRetrieveObjectByUrlA"

// колбэки для CryptRetrieveObjectByUrlA
typedef BOOL (WINAPI RetrieveObjectByUrlACallback_t)(
    LPCSTR pszUrl,
    LPCSTR pszObjectOid,
    DWORD dwRetrievalFlags,
    DWORD dwTimeout,
    LPVOID* ppvObject,
    HCRYPTASYNC hAsyncRetrieve,
    PCRYPT_CREDENTIALS pCredentials,
    LPVOID pvVerify,
    PCRYPT_RETRIEVE_AUX_INFO pAuxInfo);

#define CP_FIELD_PRESENT(ptr, field) \
    ((char*)(ptr) + (ptr)->cbSize >= (char*)(&(ptr)->field + 1))
#define CP_FIELD_PRESENT_DWSIZE(ptr, field) \
    ((char*)(ptr) + (ptr)->dwSize >= (char*)(&(ptr)->field + 1))

// TODO: перенести в CSP_WinCrypt.h после отказа от поддержки Vista/2008

//
// Time stamp API
//

#ifndef TIMESTAMP_VERSION

//+-------------------------------------------------------------------------
//  CRYPT_TIMESTAMP_REQUEST
//
//--------------------------------------------------------------------------
#define TIMESTAMP_VERSION  1

typedef struct _CRYPT_TIMESTAMP_REQUEST
{
    DWORD                       dwVersion;              // v1
    CRYPT_ALGORITHM_IDENTIFIER  HashAlgorithm;
    CRYPT_DER_BLOB              HashedMessage;
    LPSTR                       pszTSAPolicyId;         // OPTIONAL
    CRYPT_INTEGER_BLOB          Nonce;                  // OPTIONAL
    BOOL                        fCertReq;               // DEFAULT FALSE
    DWORD                       cExtension;
    PCERT_EXTENSION             rgExtension;            // OPTIONAL
} CRYPT_TIMESTAMP_REQUEST, *PCRYPT_TIMESTAMP_REQUEST;

//+-------------------------------------------------------------------------
//  CRYPT_TIMESTAMP_RESPONSE
//
//--------------------------------------------------------------------------
typedef struct _CRYPT_TIMESTAMP_RESPONSE
{
    DWORD                       dwStatus;
    DWORD                       cFreeText;              // OPTIONAL
    LPWSTR*                     rgFreeText;
    CRYPT_BIT_BLOB              FailureInfo;            // OPTIONAL
    CRYPT_DER_BLOB              ContentInfo;            // OPTIONAL
} CRYPT_TIMESTAMP_RESPONSE, *PCRYPT_TIMESTAMP_RESPONSE;

#define TIMESTAMP_STATUS_GRANTED                        0
#define TIMESTAMP_STATUS_GRANTED_WITH_MODS              1
#define TIMESTAMP_STATUS_REJECTED                       2
#define TIMESTAMP_STATUS_WAITING                        3
#define TIMESTAMP_STATUS_REVOCATION_WARNING             4
#define TIMESTAMP_STATUS_REVOKED                        5

#define TIMESTAMP_FAILURE_BAD_ALG                       0
#define TIMESTAMP_FAILURE_BAD_REQUEST                   2
#define TIMESTAMP_FAILURE_BAD_FORMAT                    5
#define TIMESTAMP_FAILURE_TIME_NOT_AVAILABLE            14
#define TIMESTAMP_FAILURE_POLICY_NOT_SUPPORTED          15
#define TIMESTAMP_FAILURE_EXTENSION_NOT_SUPPORTED       16
#define TIMESTAMP_FAILURE_INFO_NOT_AVAILABLE            17
#define TIMESTAMP_FAILURE_SYSTEM_FAILURE                25

//+-------------------------------------------------------------------------
//  CRYPT_TIMESTAMP_ACCURACY
//
//--------------------------------------------------------------------------
typedef struct _CRYPT_TIMESTAMP_ACCURACY
{
    DWORD                       dwSeconds;                  // OPTIONAL
    DWORD                       dwMillis;                   // OPTIONAL
    DWORD                       dwMicros;                   // OPTIONAL
} CRYPT_TIMESTAMP_ACCURACY, *PCRYPT_TIMESTAMP_ACCURACY;

//+-------------------------------------------------------------------------
//  CRYPT_TIMESTAMP_INFO
//
//--------------------------------------------------------------------------
typedef struct _CRYPT_TIMESTAMP_INFO
{
    DWORD                       dwVersion;                  // v1
    LPSTR                       pszTSAPolicyId;
    CRYPT_ALGORITHM_IDENTIFIER  HashAlgorithm;
    CRYPT_DER_BLOB              HashedMessage;
    CRYPT_INTEGER_BLOB          SerialNumber;
    FILETIME                    ftTime;
    PCRYPT_TIMESTAMP_ACCURACY   pvAccuracy;                 // OPTIONAL
    BOOL                        fOrdering;                  // OPTIONAL
    CRYPT_DER_BLOB              Nonce;                      // OPTIONAL
    CRYPT_DER_BLOB              Tsa;                        // OPTIONAL
    DWORD                       cExtension;
    PCERT_EXTENSION             rgExtension;                // OPTIONAL
} CRYPT_TIMESTAMP_INFO, *PCRYPT_TIMESTAMP_INFO;

//+-------------------------------------------------------------------------
//  CRYPT_TIMESTAMP_CONTEXT
//
//--------------------------------------------------------------------------
typedef struct _CRYPT_TIMESTAMP_CONTEXT
{
    DWORD                       cbEncoded;
    BYTE                        *pbEncoded;
    PCRYPT_TIMESTAMP_INFO       pTimeStamp;
} CRYPT_TIMESTAMP_CONTEXT, *PCRYPT_TIMESTAMP_CONTEXT;

//+-------------------------------------------------------------------------
//  CRYPT_TIMESTAMP_PARA
//
//  pszTSAPolicyId
//      [optional] Specifies the TSA policy under which the time stamp token
//      should be provided.
//
//  Nonce
//      [optional] Specifies the nonce value used by the client to verify the
//      timeliness of the response when no local clock is available.
//
//  fCertReq
//      Specifies whether the TSA must include in response the certificates
//      used to sign the time stamp token.
//
//  rgExtension
//      [optional]  Specifies Extensions to be included in request.

//--------------------------------------------------------------------------
typedef struct _CRYPT_TIMESTAMP_PARA
{
    LPCSTR                      pszTSAPolicyId;             // OPTIONAL
    BOOL                        fRequestCerts;              // Default is TRUE
    CRYPT_INTEGER_BLOB          Nonce;                      // OPTIONAL
    DWORD                       cExtension;
    PCERT_EXTENSION             rgExtension;                // OPTIONAL
} CRYPT_TIMESTAMP_PARA, *PCRYPT_TIMESTAMP_PARA;

#endif // TIMESTAMP_VERSION

#endif /* _WINCRYPTEX_H_INCLUDED */
/** \endcond */
