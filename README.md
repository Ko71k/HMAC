Заранее необходимо установить КриптоПро CSP: https://cryptopro.ru/products/csp/downloads#latest_csp50r3

myCreatingHash.c = пример получения хэша

selfmade_Hmac.c = реализация HMAC на основе ГОСТ Р 34.11-2012 (CALG_GR3411_2012_256)

built_in_hmac.c = реализация HMAC на основе встроенного алгоритма CALG_GR3411_2012_256_HMAC

filereader.c = модификация selfmade_Hmac.c, принимающая ключ как ещё один параметр.

WinCryptEx.h = CryptoPro CSP WinCrypt.h extensions

test.txt = необязательный файл, нужен для демонстрации работы, из него берутся данные для хэширования
somkey.txt = необязательный файл, нужен для демонстрации работы, из него берётся ключ для хэширования

Компиляция
```
gcc .\selfmade_Hmac.c -o self
gcc .\built_in_hmac.c -o bltn
```
Запуск
```
.\self test.txt
.\bltn test.txt
```
Первая версия импорта ключа из внешнего файла
```
gcc filereader.c -o flrdr
.\flrdr.exe test.txt somkey.txt
```
Результат совпал с built_in_mac при одинаковых ключах (все 'a' и все '0')

В cross_check вместе слеплены selfmade_Hmac.c и built_in_hmac.c, а также программа ожидает на вход 3 параметра, подобно filereader.c
```
gcc .\cross_check.c -o cc
.\cc.exe .\test.txt .\somkey.txt
```
Если длина ключа > 32 байт, то для получения HMAC ключ хэшируется. Иначе дополняется нулями до 32.
