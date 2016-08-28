﻿using System.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace ITfoxtec.Identity.Saml2.Cryptography
{
    public class Saml2SignedXml : SignedXml
    {
        public Saml2SignedXml()
        {
            AddAlgorithm();
        }

        public Saml2SignedXml(XmlDocument document) : base(document)
        {
            AddAlgorithm();
        }

        public Saml2SignedXml(XmlElement element) : base(element)
        {
            AddAlgorithm();
        }

        private void AddAlgorithm()
        {
            CryptoConfig.AddAlgorithm(typeof(RSAPKCS1SHA1SignatureDescription), SecurityAlgorithms.RsaSha1Signature);
            CryptoConfig.AddAlgorithm(typeof(RSAPKCS1SHA256SignatureDescription), SecurityAlgorithms.RsaSha256Signature);
        }

        public void ComputeSignature(X509Certificate2 certificate, X509IncludeOption includeOption, string id, string signatureMethod)
        {
            SigningKey = certificate.GetCertificatePrivateKey();
            
            SignedInfo.CanonicalizationMethod = XmlDsigExcC14NTransformUrl;
            SignedInfo.SignatureMethod = signatureMethod;

            var reference = new Reference("#" + id) {DigestMethod = SignatureAlgorithm.DigestMethod(signatureMethod)};
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform());

            AddReference(reference);
            ComputeSignature();

            KeyInfo = new KeyInfo();
            KeyInfo.AddClause(new KeyInfoX509Data(certificate, includeOption));
        }

        public bool CheckSignature(X509Certificate2 certificate)
        {
            try
            {
                return CheckSignature(certificate, true);
            }
            catch (CryptographicException cExc)
            {
                throw new CryptographicException("SHA256 algorithm is not supported.", cExc);
            }
        }
    }
}
