using main;
namespace tests;

public class Tests
{
    readonly string KEYS_DIR = Path.Combine(Directory.GetParent(Environment.CurrentDirectory).Parent.Parent.FullName, "keys");
    readonly string PROJ_DIR= Directory.GetParent(Environment.CurrentDirectory).Parent.Parent.FullName;
    string key1 = "";
    string cert1 = "";
    string key2 = "";
    string cert2 = "";

    [SetUp]
    public void Setup()
    {
        key1 = Path.Combine(KEYS_DIR, "private-key.pem");
        key2 = Path.Combine(KEYS_DIR, "private-key-2.pem");
        cert1 = Path.Combine(KEYS_DIR, "cert.pem");
        cert2 = Path.Combine(KEYS_DIR, "cert-2.pem");
    }
    

    [Test]
    public void Default()
    {
        string inputFile = Path.Combine(PROJ_DIR, "test.xml");
        string signedFile = Path.Combine(Environment.CurrentDirectory, "signed.xml");
        XMLsig.Main(new[] { "s", inputFile, key1 });
        Assert.That(XMLsig.Main(new[] { "v", signedFile, cert1}), Is.Zero);
    }
    [Test]
    public void ValWithPriv()
    {
        string inputFile = Path.Combine(PROJ_DIR, "test.xml");
        string signedFile = Path.Combine(Environment.CurrentDirectory, "signed.xml");
        XMLsig.Main(new[] { "s", inputFile, key1 });
        Assert.That(XMLsig.Main(new[] { "v", signedFile, "-private", key1 }), Is.Zero);
    }
    [Test]
    public void ValWithWrongCert()
    {
        string inputFile = Path.Combine(PROJ_DIR, "test.xml");
        string signedFile = Path.Combine(Environment.CurrentDirectory, "signed.xml");
        XMLsig.Main(new[] { "s", inputFile, key1 });
        Assert.That(XMLsig.Main(new[] { "v", signedFile, cert2 }), Is.Not.Zero);
    }
    [Test]
    public void MultipleRefs()
    {
        string inputFile = Path.Combine(PROJ_DIR, "test.xml");
        string signedFile = Path.Combine(Environment.CurrentDirectory, "signed.xml");
        XMLsig.Main(new[] { "s", inputFile, key1, "-refs", "#credit"});
        Assert.That(XMLsig.Main(new[] { "v", signedFile, cert1 }), Is.Zero);
    }
}
