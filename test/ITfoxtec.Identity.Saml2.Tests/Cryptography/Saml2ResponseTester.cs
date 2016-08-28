using ITfoxtec.Identity.Saml2.Configuration;
using ITfoxtec.Identity.Saml2.Request;

namespace ITfoxtec.Identity.Saml2.Tests.Cryptography
{
    public class Saml2ResponseTester : Saml2AuthnResponse
    {
        public Saml2ResponseTester(Saml2Configuration config) : base(config)
        {
        }

        public void ReadPublicly(string xml, bool validateXmlSignature)
        {
            Read(xml, validateXmlSignature);
        }
    }
}