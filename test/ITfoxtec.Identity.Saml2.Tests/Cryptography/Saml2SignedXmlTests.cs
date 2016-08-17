using System.Collections;
using System.IdentityModel.Tokens;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using ITfoxtec.Identity.Saml2.Cryptography;
using ITfoxtec.Identity.Saml2.Cryptography.Cryptography;
using ITfoxtec.Identity.Saml2.Extensions;
using ITfoxtec.Identity.Saml2.Util;
using NUnit.Framework;

namespace ITfoxtec.Identity.Saml2.Tests.Cryptography
{
    [TestFixture]
    public class Saml2SignedXmlTests
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
        public void ComputeSignature_ForDifferentCertificatesAndSignatures_ShouldWork(string certificatePath, string signatureAlgorithm)
        {
            const string xmlString = "<root id=\"a1\"><test></test></root>";

            var certificate = CertificateUtil.Load(MapPath(certificatePath), "123");
            var xml = xmlString.ToXmlDocument().DocumentElement;
            var sut = new Saml2SignedXml(xml);

            Assert.DoesNotThrow(() => sut.ComputeSignature(certificate, X509IncludeOption.EndCertOnly, "a1", signatureAlgorithm));
            Assert.That(sut.CheckSignature(), Is.True);
        }

        private string MapPath(string relativePath) => Path.Combine(TestContext.CurrentContext.TestDirectory, relativePath);
    }
}