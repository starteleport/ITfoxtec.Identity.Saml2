using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Security.Cryptography;
using Security.Cryptography.X509Certificates;

namespace ITfoxtec.Identity.Saml2.Cryptography
{
    public static class X509CertificateExtensions
    {
        public static AsymmetricAlgorithm GetCertificatePrivateKey(this X509Certificate2 certificate)
        {
            if (!certificate.HasCngKey())
                return certificate.PrivateKey;

            var key = certificate.GetCngPrivateKey();
            return new RSACng(key) {EncryptionPaddingMode = AsymmetricPaddingMode.Pkcs1};
        }
    }
}