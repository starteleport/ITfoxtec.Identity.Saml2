using System.IO;
using ITfoxtec.Identity.Saml2.Configuration;
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
            var signedXml = File.ReadAllText(MapPath(@"TestFiles\saml2Response.xml"));
            var certificate = CertificateUtil.Load(MapPath(@"TestFiles\okta.cert"));
            var sut = new Saml2ResponseTester(new Saml2Configuration())
            {
                SignatureValidationCertificates = new[] {certificate}
            };

            sut.ReadPublicly(signedXml, true);
        }

        private string MapPath(string relativePath) => Path.Combine(TestContext.CurrentContext.TestDirectory, relativePath);
    }
}