# lockr
Encrypt files with a ChaCha20 256-bit key, Poly 1305 128-bit tag and a 192-bit XChaCha20 nonce 


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
