using System.Security.Cryptography;
using System.Xml;
using System.Security.Cryptography.Xml;
using System.Security.Cryptography.X509Certificates;

/*
 * Create RSA (private key)
 * openssl genrsa -out private-key.pem 3072
 * 
 * Create X509 (public key)
 * openssl req -new -x509 -key private-key.pem -out cert.pem -days 360
 * 
 * ./xml-sig s file.xml private-key.pem
 * ./xml-sig v file.xml cert.pem
 * 
 */
namespace main
{
    
    public class XMLsig
    {
        public static int Main(string[] args)
        {
            string usage =
                    "xml-sig s file.xml private-key.pem [-ek]   (-ek embed X509 cert in KeyInfo)\n" +
                    "xml-sig v file.xml                         (implicit X509 cert in file)\n" +
                    "xml-sig v file.xml public-key.pem          (public X509 cert)";

            if (args.Length < 2)
            {
                Console.WriteLine(usage);
                return 1;
            }
            string method = args[0];
            string xmlFile = args[1];
            string keyFile;
            // Tomma strängen betyder att vi signerar hela filen, ta inte bort
            List<string> references = new() { "" };

            switch (method.ToLower())
            {
                case "s":
                case "sign":
                    keyFile = args[2];
                    var rsaKey = LoadRSAKeys(File.ReadAllText(keyFile));
                    var xmlDoc = LoadXml(xmlFile);
                    Sign(ref xmlDoc, rsaKey, references, args.Contains("-ek"));

                    xmlDoc.Save("signed.xml");
                    Console.WriteLine($"signed.xml"); // Full-url
                    break;

                case "v":
                case "validate":
                    var xmlDoc_v = LoadXml(xmlFile);
                    bool isValid;

                    // Med ett utpekat publikt cert
                    if (args.Length > 2)
                    {
                        keyFile = args[2];
                        var pubCert = new X509Certificate2(keyFile);
                        isValid = Validate(xmlDoc_v, pubCert);
                    }
                    // Certet hämtas från inuti signaturen
                    else
                    {
                        isValid = Validate(xmlDoc_v);
                    }

                    Console.WriteLine(isValid);
                    return isValid ? 0 : 1; // Om valid = OK (0)

                default:
                    Console.WriteLine(usage);
                    break;
            }
            return 0;
        }
        static void Sign(ref XmlDocument file, RSA privateKey, List<string> references, bool embeddKey)
        {
            SignedXml signedXml = new(file)
            {
                SigningKey = privateKey
            };
            if (signedXml.SignedInfo == null)
            {
                throw new Exception("No 'SignedInfo' tag"); // Should not happen
            }
            signedXml.SignedInfo.CanonicalizationMethod = "http://www.w3.org/2001/10/xml-exc-c14n#";
            signedXml.SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

            // Kopiera och ändra URI för fler referencer/digests
            foreach (var reference in references)
            {
                var _reference = new Reference
                {
                    Uri = reference
                };
                _reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
                _reference.AddTransform(new XmlDsigExcC14NTransform());
                signedXml.AddReference(_reference);
            }

            if (embeddKey) {
            // Create a self-signed certificate
            // Måste göras för att konvertera den privata RSA-nyckeln till ett certifikat
            // Detta motsvarar: 'openssl req -new -x509 -key private-key.pem -out cert.pem -years 1'
                var certRequest = new CertificateRequest("CN=SelfSignedCert", privateKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                X509Certificate2 cert = certRequest.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));

                // Lägger till KeyInfo-taggar, som kan användas vid validering
                KeyInfo ki = new KeyInfo();
                //ki.AddClause(new RSAKeyValue(privateKey));
                ki.AddClause(new KeyInfoX509Data(cert));
                signedXml.KeyInfo = ki;
            }
            
            signedXml.ComputeSignature();

            // Ändra till taggen man vill lägga referensen i.
            // I IVI ligger den under root så detta bör vara korrekt
            file.DocumentElement?.AppendChild(signedXml.GetXml());
            return;
        }


        // https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.xml.signedxml.checksignature?view=net-7.0
        // 'This method also computes the digest of the references and the value of the signature.'
        static bool Validate(XmlDocument file, X509Certificate2? certificate = null)
        {
            var signedXml = new SignedXml(file);

            var signatureElement = file.GetElementsByTagName("Signature");
            if (signatureElement.Count != 1)
            {
                throw new Exception("Not exactly 1 Signature tag");
            }
            signedXml.LoadXml((XmlElement)signatureElement[0]);

            Console.WriteLine($"# References: {signedXml.SignedInfo.References.Count}");
            if (signedXml.SignedInfo.References.Count < 1)
            {
                throw new Exception("No references");
            }
            // Testa. 
            // Flagga att inte embedda nkeyinfo
            // Plockar ut certifikatet om det finns och gör det till rätt keytype
            X509Certificate2? ExtractKey()
            {
                foreach (KeyInfoClause clause in signedXml.KeyInfo)
                {
                    if (clause is KeyInfoX509Data keyInfoX509Data)
                    {
                        foreach (X509Certificate2 cert in keyInfoX509Data.Certificates)
                        {
                            // Do something with the certificate
                            Console.WriteLine(cert.Subject);
                            return cert;
                        }
                    }
                }
                return null;
            }
                // Om vi inte pekar ut ett nyckelpar så söker vi i filen efter certet
            if (certificate is null)
            {
                certificate ??= ExtractKey();
            }

            // Om vi inte hittar något cert i filen och inte har pekat ut
            if(certificate is null)
            {
                throw new Exception("No public key");
            }

            // Validerar signaturen
            // Måste sätta true eftersom vi använder selfsigned cert
            bool isValid = signedXml.CheckSignature(certificate, true);
            // Ta bort private delarna och gör mot certet här
            //bool isValid = signedXml.CheckSignature(publicKey);
            
            return isValid;
        }

        static RSA LoadRSAKeys(string content)
        {
            var rsaKey = RSA.Create();
            rsaKey.ImportFromPem(content);
            return rsaKey;
        }

        static XmlDocument LoadXml(string filePath)
        {
            XmlDocument doc = new()
            {
                PreserveWhitespace = true
            };
            doc.Load(filePath);
            return doc;
        }
    }
}