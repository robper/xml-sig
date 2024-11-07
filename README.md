Kan användas för att signera och validera en godtycklig XML-fil.

En exempelfil medföljer, men vilken som bör fungera, inclusive EUCARIS IVI.



# Skapa certifikat
Två nyckelpar (RSA) finns i /tests/keys, dessa kan användas för att signera och validera signaturen.
Vill ni skapa egna nycklar kan ni mha OpenSSL göra:

Create RSA (private key)
```
openssl genrsa -out private-key.pem 3072
```

Create X509 (public key)
```
openssl req -new -x509 -key private-key.pem -out cert.pem -days 360
```
 
# Användning
xml-sig s file.xml private-key.pem [-ek]    (-ek lägger in publika certet i KeyInfo)
xml-sig v file.xml                          (implicit cert in file)
xml-sig v file.xml public-key.pem           (public cert)



Normal användning:  
Ta fram den XML ni vill signera.  
Signera den med 's' och den privata nyckeln.  
Validera signaturen 'v' med den publika nyckeln.  

# Tests
Signera utan ek
    Validera med public, OK
    Validera utan, gör ändring i filen, FEL
    Validera utan, FEL
    Validera med fel public, FEL
Signera med ek
    Validera utan, OK
    Validera utan, gör ändring i filen, FEL
    (Validera med public) bara för att, OK
    (Validera med fel public) bara för att, FEL
