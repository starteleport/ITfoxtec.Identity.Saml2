using System;
using System.Collections;
using System.IdentityModel.Tokens;
using System.Text;
using ITfoxtec.Identity.Saml2.Cryptography;
using ITfoxtec.Identity.Saml2.Util;
using NUnit.Framework;

namespace ITfoxtec.Identity.Saml2.Tests.Cryptography
{
    [TestFixture]
    public class Saml2SignedTextTests
    {
        private const string CngCertificate = "TestFiles\\saml-test.pfx";
        private const string LegacyCertificate = "TestFiles\\legacy-saml-test.pfx";

        public static IEnumerable TestCases
        {
            get
            {
                yield return new TestCaseData(LegacyCertificate, SecurityAlgorithms.RsaSha256Signature).SetName("Legacy SHA256");
                yield return new TestCaseData(LegacyCertificate, SecurityAlgorithms.RsaSha1Signature).SetName("Legacy SHA1");
                yield return new TestCaseData(CngCertificate, SecurityAlgorithms.RsaSha256Signature).SetName("CNG SHA256");
                yield return new TestCaseData(CngCertificate, SecurityAlgorithms.RsaSha1Signature).SetName("CNG SHA1");
            }
        }

        [TestCaseSource(nameof(TestCases))]
        public void SignData_ForDifferentCertificatesAndSignatures_ShouldWork(string certificatePath, string signatureAlgorithm)
        {
            var certificate = CertificateUtil.Load(TestFile.MapPath(LegacyCertificate), "123");
            var sut = new Saml2SignedText(certificate, signatureAlgorithm);
            var signingText = Guid.NewGuid().ToString();
            var bytesToSign = Encoding.UTF8.GetBytes(signingText);

            Assert.DoesNotThrow(() => sut.SignData(bytesToSign));
            var signature = sut.SignData(bytesToSign);
            Assert.That(sut.CheckSignature(signingText, signature), Is.True);
        }
    }
}