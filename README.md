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
