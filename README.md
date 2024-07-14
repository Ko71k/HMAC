Заранее необходимо установить КриптоПро CSP: https://cryptopro.ru/products/csp/downloads#latest_csp50r3

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
