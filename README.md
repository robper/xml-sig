Kan användas för att signera och validera en godtycklig XML-fil.

En exempelfil och 2 nyckelpar medföljer under /tests/keys och /test/text.xml.

# Skapa certifikat

Två nyckelpar (RSA) finns i /tests/keys, dessa kan användas för att signera och validera signaturen.
Vill ni skapa egna nycklar kan ni mha OpenSSL göra:

Create RSA (private key)

    openssl genrsa -out private-key.pem 3072

Create X509 (public key)

    openssl req -new -x509 -key private-key.pem -out cert.pem -days 360

# Användning

    xml-sig s file.xml private-key.pem [-ek]    (-ek embed X509 cert in KeyInfo)
    xml-sig v file.xml                          (implicit X509 cert in file)
    xml-sig v file.xml public-key.pem           (public X509 cert)

## Normal användning:  

1. Ta fram den XML ni vill signera.  
2. Signera den med 's' och den privata nyckeln.  
3. Validera signaturen 'v' med den publika nyckeln eller den som finns i filen.  

# Tests

## Signera utan ek

* Validera med public, OK
* Validera utan, gör ändring i filen, FEL
* Validera utan, FEL
* Validera med fel public, FEL

## Signera med ek

* Validera utan, OK
* Validera utan, gör ändring i filen, FEL
* Validera med public, OK
* Validera med fel public, FEL
