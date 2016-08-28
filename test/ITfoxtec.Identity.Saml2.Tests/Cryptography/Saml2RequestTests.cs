using System.IO;
using ITfoxtec.Identity.Saml2.Configuration;
using ITfoxtec.Identity.Saml2.Request;
using ITfoxtec.Identity.Saml2.Util;
using NUnit.Framework;

namespace ITfoxtec.Identity.Saml2.Tests.Cryptography
{
    [TestFixture]
    public class Saml2RequestTests
    {

        [Test]
        public void CheckSignature_ForSignedResponseWithSignedAssertion_ShouldWork()
        {
            var signedXml = File.ReadAllText(TestFile.MapPath(@"TestFiles\saml2Response.xml"));
            var certificate = CertificateUtil.Load(TestFile.MapPath(@"TestFiles\okta.cert"));
            var sut = new Saml2ResponseTester(new Saml2Configuration())
            {
                SignatureValidationCertificates = new[] {certificate}
            };

            var ex = Assert.Throws<Saml2RequestException>(() => sut.ReadPublicly(signedXml, true));
            Assert.That(ex.Message, Does.Contain("Assertion has expired"));
        }
    }
}