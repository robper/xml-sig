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
                    "xml-sig s file.xml private-key.pem -refs [ref1, ref2...]\n" +
                    "xml-sig v file.xml -private private-key.pem (full RSA key)\n" +
                    "xml-sig v file.xml public-key.pem (public key/cert)";

            if (args.Length < 3)
            {
                Console.WriteLine(usage);
                return 1;
            }
            string method = args[0];
            string xmlFile = args[1];
            string keyFile = "";
            List<string> references = new() { "" }; // Default full doc

            switch (method.ToLower())
            {
                case "s":
                case "sign":
                    if (args.Length >= 4 && args[3] == "-refs")
                    {
                        references.AddRange(args[4].Split(','));
                    }
                    keyFile = args[2];
                    var rsaKey = LoadRSAKeys(File.ReadAllText(keyFile));
                    var xmlDoc = LoadXml(xmlFile);
                    Sign(ref xmlDoc, rsaKey, references);

                    xmlDoc.Save("signed.xml");
                    Console.WriteLine($"signed.xml"); // Full-url
                    break;

                case "v":
                case "validate":
                    var xmlDoc_v = LoadXml(xmlFile);
                    bool isValid;
                    if (args[2] == "-private")
                    {
                        keyFile = args[3];
                        var rsaKey_v = LoadRSAKeys(File.ReadAllText(keyFile));
                        isValid = Validate(xmlDoc_v, rsaKey_v);

                    }
                    else
                    {
                        keyFile = args[2];
                        var pubCert = new X509Certificate2(keyFile);
                        isValid = Validate(xmlDoc_v, pubCert);
                    }

                    Console.WriteLine(isValid);
                    return isValid ? 0 : 1;

                default:
                    Console.WriteLine(usage);
                    break;
            }
            return 0;
        }
        static void Sign(ref XmlDocument file, RSA privateKey, List<string> references)
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

            // Create a self-signed certificate
            // Måste göras för att konvertera RSA-nycklar till ett certifikat
            // Detta motsvarar: 'openssl req -new -x509 -key private-key.pem -out cert.pem -years 1'
            var request = new CertificateRequest("CN=SelfSignedCert", privateKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            X509Certificate2 cert = request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));

            //signedXml.SigningKey = privateKey; // Vad gör den?

            // Lägger till KeyInfo-taggar, som kan användas vid validering
            KeyInfo ki = new KeyInfo();
            ki.AddClause(new RSAKeyValue(privateKey));
            ki.AddClause(new KeyInfoX509Data(cert));
            signedXml.KeyInfo = ki;
            
            signedXml.ComputeSignature();

            // Ändra till taggen man vill lägga referensen i.
            // I IVI ligger den under root så detta bör vara korrekt
            file.DocumentElement?.AppendChild(signedXml.GetXml());
            return;
        }

        static bool Validate(XmlDocument file, X509Certificate2 certificate)
        {
            if(certificate.GetRSAPublicKey() == null)
            {
                throw new Exception("No public key found!");
            }
            return Validate(file, certificate.GetRSAPublicKey());
        }

        // https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.xml.signedxml.checksignature?view=net-7.0
        // 'This method also computes the digest of the references and the value of the signature.'
        static bool Validate(XmlDocument file, RSA publicKey)
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
            bool isValid = signedXml.CheckSignature(publicKey); // Validerar alla referenser och signaturen
            foreach (Reference reference in signedXml.SignedInfo.References)
            {
                Console.WriteLine($"Reference URI '{reference.Uri}'");
            }
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