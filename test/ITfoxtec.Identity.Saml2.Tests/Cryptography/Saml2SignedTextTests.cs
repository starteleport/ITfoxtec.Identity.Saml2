using System;
using System.IdentityModel.Tokens;
using System.IO;
using System.Text;
using ITfoxtec.Identity.Saml2.Cryptography;
using ITfoxtec.Identity.Saml2.Util;
using NUnit.Framework;

namespace ITfoxtec.Identity.Saml2.Tests.Cryptography
{
    [TestFixture]
    public class Saml2SignedTextTests
    {
        [TestCase(SecurityAlgorithms.RsaSha256Signature)]
        [TestCase(SecurityAlgorithms.RsaSha1Signature)]
        public void ComputeSignature_ForRsaShaSignatures_ShouldWork(string signatureAlgorithm)
        {
            var certificate = CertificateUtil.Load(MapPath("TestFiles\\saml-test.pfx"), "123");
            var sut = new Saml2SignedText(certificate, signatureAlgorithm);
            var bytesToSign = Encoding.UTF8.GetBytes(Guid.NewGuid().ToString());

            sut.SignData(bytesToSign);

            Assert.DoesNotThrow(() => sut.SignData(bytesToSign));
        }

        private string MapPath(string relativePath) => Path.Combine(TestContext.CurrentContext.TestDirectory, relativePath);
    }
}