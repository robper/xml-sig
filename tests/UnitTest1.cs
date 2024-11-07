using System.Xml;
using main;
namespace tests;

public class Tests
{
    readonly string KEYS_DIR = Path.Combine(Directory.GetParent(Environment.CurrentDirectory).Parent.Parent.FullName, "keys");
    readonly string PROJ_DIR = Directory.GetParent(Environment.CurrentDirectory).Parent.Parent.FullName;
    string key1 = "";
    string cert1 = "";
    string key2 = "";
    string cert2 = "";
    string inputFile = "";
    string signedFile = "";

    /// <summary>
    /// Not.Zero indikerar ett fel
    /// Zero betyder att det gått bra
    /// </summary>
    [SetUp]
    public void Setup()
    {
        key1 = Path.Combine(KEYS_DIR, "private-key.pem");
        key2 = Path.Combine(KEYS_DIR, "private-key-2.pem");
        cert1 = Path.Combine(KEYS_DIR, "cert.pem");
        cert2 = Path.Combine(KEYS_DIR, "cert-2.pem");
        inputFile = Path.Combine(PROJ_DIR, "test.xml");
        signedFile = Path.Combine(Environment.CurrentDirectory, "signed.xml");
    }


    [Test]
    public void NoEKNoCert()
    {
        XMLsig.Main(new[] { "s", inputFile, key1 });
        var ex = Assert.Throws<Exception>(() => XMLsig.Main(new[] { "v", signedFile }));
        Assert.That(ex.Message, Is.EqualTo("No public key"));

    }
    [Test]
    public void NoEKPublicCert()
    {
        XMLsig.Main(new[] { "s", inputFile, key1 });
        var returnVal = XMLsig.Main(new[] { "v", signedFile, cert1 });
        Assert.That(returnVal, Is.Zero);
    }
    [Test]
    public void NoEKPublicCert_Manipulate()
    {
        XMLsig.Main(new[] { "s", inputFile, key1 });
        XmlDocument doc = new()
        {
            PreserveWhitespace = true
        };
        doc.Load(signedFile);
        doc.SelectSingleNode("//creditcard/number").InnerText = "1";
        doc.Save(signedFile);
        var returnVal = XMLsig.Main(new[] { "v", signedFile, cert1 });
        Assert.That(returnVal, Is.Not.Zero);
    }
    [Test]
    public void NoEKWrongCert()
    {
        XMLsig.Main(new[] { "s", inputFile, key1 });
        var returnVal = XMLsig.Main(new[] { "v", signedFile, cert2 });
        Assert.That(returnVal, Is.Not.Zero);
    }


    [Test]
    public void EKNoCert()
    {
        XMLsig.Main(new[] { "s", inputFile, key1, "-ek" });
        var returnVal = XMLsig.Main(new[] { "v", signedFile });
        Assert.That(returnVal, Is.Zero);
    }

    [Test]
    public void EKPublicCert()
    {
        XMLsig.Main(new[] { "s", inputFile, key1, "-ek" });
        var returnVal = XMLsig.Main(new[] { "v", signedFile, cert1 });
        Assert.That(returnVal, Is.Zero);
    }
    [Test]
    public void EKWrongPublicCert()
    {
        XMLsig.Main(new[] { "s", inputFile, key1, "-ek" });
        var returnVal = XMLsig.Main(new[] { "v", signedFile, cert2 });
        Assert.That(returnVal, Is.Not.Zero);
    }

    [Test]
    public void EKNoCert_Manipulated()
    {
        XMLsig.Main(new[] { "s", inputFile, key1, "-ek" });
        XmlDocument doc = new()
        {
            PreserveWhitespace = true
        };
        doc.Load(signedFile);
        doc.SelectSingleNode("//creditcard/number").InnerText = "1";
        doc.Save(signedFile);
        var returnVal = XMLsig.Main(new[] { "v", signedFile });
        Console.WriteLine(returnVal);
        Assert.That(returnVal, Is.Not.Zero);
    }
}
