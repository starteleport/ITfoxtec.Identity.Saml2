using System.IO;
using System.Linq;
using System.Xml;
using ITfoxtec.Identity.Saml2.Extensions;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using NUnit.Framework;

namespace ITfoxtec.Identity.Saml2.Tests.Schemas.Metadata
{
    [TestFixture]
    public class IdPSsoDescriptorTests
    {
        [Test]
        public void Read_ForWhitespaceNodeNearCertificate_ShouldReadCert()
        {
            var xmlString = File.ReadAllText(TestFile.MapPath("TestFiles\\Metadata.xml"));
            var metadata = xmlString.ToXmlDocument();

            var actual = new IdPSsoDescriptor().Read((XmlElement)metadata.GetElementsByTagName("IDPSSODescriptor")[0]);

            Assert.That(actual.SigningCertificates.Count(), Is.EqualTo(1));
        }
    }
}