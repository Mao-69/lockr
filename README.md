# lockr
Encrypt files with a ChaCha20 256-bit key, Poly 1305 128-bit tag and a 192-bit XChaCha20 nonce 

```
gcc -O2 -o lockr lockr.c -lm
```
```
./lockr
```

```
 /$$                           /$$                
| $$                          | $$                
| $$        /$$$$$$   /$$$$$$$| $$   /$$  /$$$$$$ 
| $$       /$$__  $$ /$$_____/| $$  /$$/ /$$__  $$
| $$      | $$  \ $$| $$      | $$$$$$/ | $$  \__/
| $$      | $$  | $$| $$      | $$_  $$ | $$      
| $$$$$$$$|  $$$$$$/|  $$$$$$$| $$ \  $$| $$      
|________/ \______/  \_______/|__/  \__/|__/      
                                                  
                                                  
Usage: ./lockr <encrypt|decrypt> <input|- > <output|- > [aadfile] [keyfile]
  '-' means stdin/stdout
  Default encrypted file: <input>.lockr
  Default key file      : <input>.key
  Uses XChaCha20-Poly1305 (192-bit nonce)
```

# Encrypting
- example of encrypting a basic text file
```
echo "this is a test" > test.txt
```
```
./lockr encrypt test.txt test.lockr - test.key
```
```
 /$$                           /$$                
| $$                          | $$                
| $$        /$$$$$$   /$$$$$$$| $$   /$$  /$$$$$$ 
| $$       /$$__  $$ /$$_____/| $$  /$$/ /$$__  $$
| $$      | $$  \ $$| $$      | $$$$$$/ | $$  \__/
| $$      | $$  | $$| $$      | $$_  $$ | $$      
| $$$$$$$$|  $$$$$$/|  $$$$$$$| $$ \  $$| $$      
|________/ \______/  \_______/|__/  \__/|__/      
                                                  
                                                  
[Lockr] Encrypting test.txt → test.lockr
[Lockr] Key   (32 bytes): 01ef023ef2fe33034d7e58fa380adc887aeb30f111fb21b87293e76c7ad283af
[Lockr] Nonce (24 bytes): 28017f2ffda96565380643b55b22611b75bbe5b90848fd96
[Lockr] Tag   (16 bytes): 06f0aa9b1f5d5fcafd3bf70000000000
[Lockr] Key saved to test.key
```

# Decrypting
```
./lockr decrypt test.lockr decrypted.txt - test.key
```
```
 /$$                           /$$                
| $$                          | $$                
| $$        /$$$$$$   /$$$$$$$| $$   /$$  /$$$$$$ 
| $$       /$$__  $$ /$$_____/| $$  /$$/ /$$__  $$
| $$      | $$  \ $$| $$      | $$$$$$/ | $$  \__/
| $$      | $$  | $$| $$      | $$_  $$ | $$      
| $$$$$$$$|  $$$$$$/|  $$$$$$$| $$ \  $$| $$      
|________/ \______/  \_______/|__/  \__/|__/      
                                                  
                                                  
[Lockr] Decrypting test.lockr → decrypted.txt
```
```
cat decrypted.txt
this is a test
```
