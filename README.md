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

./xml-sig s file.xml private-key.pem
./xml-sig v file.xml cert.pem
  
 
# Användning
./xml-sig s file.xml private-key.pem -refs [ref1, ref2...]  (refs optional, always signs full document)  
./xml-sig v file.xml public-key.pem                         (public key/cert)  
./xml-sig v file.xml -private private-key.pem               (full RSA key)  

Exempel på refs: '-refs #credit', refererar till en XML-nod med id 'credit'. https://www.w3.org/TR/xmldsig-core/#sec-URI

Normal användning:  
Ta fram den XML ni vill signera.  
Signera den med 's' och den privata nyckeln.  
Validera signaturen 'v' med den publika nyckeln.  
