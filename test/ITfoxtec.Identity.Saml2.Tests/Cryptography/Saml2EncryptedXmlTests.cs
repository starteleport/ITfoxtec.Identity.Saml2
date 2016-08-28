using System.IO;
using System.Security.Cryptography;
using ITfoxtec.Identity.Saml2.Cryptography;
using ITfoxtec.Identity.Saml2.Extensions;
using ITfoxtec.Identity.Saml2.Util;
using NUnit.Framework;

namespace ITfoxtec.Identity.Saml2.Tests.Cryptography
{
    [TestFixture]
    public class Saml2EncryptedXmlTests
    {
        private const string CngCertificate = "TestFiles\\saml-test.pfx";
        private const string LegacyCertificate = "TestFiles\\legacy-enc-saml-test.pfx";

        [TestCase(LegacyCertificate, TestName = "Legacy")]
        [TestCase(CngCertificate, TestName = "CNG")]
        public void EncryptAndDecrypt_ForDifferentCertificates_ShouldWork(string certificatePath)
        {
            const string xmlString = "<root id=\"a1\"><test /></root>";

            var certificate = CertificateUtil.Load(MapPath(certificatePath), "123");
            var xml = xmlString.ToXmlDocument();
            var sut = new Saml2EncryptedXml(xml, (RSA)certificate.GetCertificatePrivateKey());

            var elementToEncrypt = xml.DocumentElement;
            var encryptedData = sut.Encrypt(elementToEncrypt, certificate);
            var encrypted = encryptedData.GetXml().OuterXml.ToXmlDocument();

            var sut2 = new Saml2EncryptedXml(encrypted, (RSA) certificate.GetCertificatePrivateKey());
            sut2.DecryptDocument();
            
            Assert.That(encrypted.OuterXml, Is.EqualTo(xml.OuterXml));
        }

        private string MapPath(string relativePath) => Path.Combine(TestContext.CurrentContext.TestDirectory, relativePath);
    }
}