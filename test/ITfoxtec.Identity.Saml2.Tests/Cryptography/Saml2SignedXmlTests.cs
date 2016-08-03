using System.IdentityModel.Tokens;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using ITfoxtec.Identity.Saml2.Cryptography;
using ITfoxtec.Identity.Saml2.Extensions;
using ITfoxtec.Identity.Saml2.Util;
using NUnit.Framework;

namespace ITfoxtec.Identity.Saml2.Tests.Cryptography
{
    [TestFixture]
    public class Saml2SignedXmlTests
    {
        [TestCase(SecurityAlgorithms.RsaSha256Signature)]
        [TestCase(SecurityAlgorithms.RsaSha1Signature)]
        public void ComputeSignature_ForRsaShaSignatures_ShouldWork(string signatureAlgorithm)
        {
            const string xmlString = "<root id=\"a1\"><test></test></root>";

            var certificate = CertificateUtil.Load(MapPath("TestFiles\\saml-test.pfx"), "123");
            var xml = xmlString.ToXmlDocument().DocumentElement;
            var sut = new Saml2SignedXml(xml, certificate, signatureAlgorithm);

            Assert.DoesNotThrow(() => sut.ComputeSignature(X509IncludeOption.EndCertOnly, "a1"));
            Assert.That(sut.CheckSignature(), Is.True);
        }

        private string MapPath(string relativePath) => Path.Combine(TestContext.CurrentContext.TestDirectory, relativePath);
    }
}