using System;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Security.Cryptography;

namespace ITfoxtec.Identity.Saml2.Cryptography
{
    public class Saml2SignedText : IDisposable
    {
        private readonly string _signatureAlgorithm;
        private readonly AsymmetricAlgorithm _algorithm;

        public Saml2SignedText(X509Certificate2 certificate, string signatureAlgorithm)
        {
            _algorithm = certificate.GetCertificatePrivateKey();
            if (_algorithm is RSACng)
            {
                _signatureAlgorithm = signatureAlgorithm ?? SecurityAlgorithms.RsaSha1Signature;

                switch (signatureAlgorithm)
                {
                    case SecurityAlgorithms.RsaSha1Signature:
                        ((RSACng) _algorithm).SignatureHashAlgorithm = CngAlgorithm.Sha1;
                        break;

                    case SecurityAlgorithms.RsaSha256Signature:
                        ((RSACng) _algorithm).SignatureHashAlgorithm = CngAlgorithm.Sha256;
                        break;

                    default:
                        throw new NotSupportedException("Only SHA1 and SHA256 is supported.");
                }
            }
            else
            {
                _signatureAlgorithm = signatureAlgorithm ?? _algorithm.SignatureAlgorithm;
            }
        }

        public byte[] SignData(byte[] data)
        {
            var rsaCryptoServiceProvider = _algorithm as RSACryptoServiceProvider;
            if (rsaCryptoServiceProvider != null)
            {
                HashAlgorithm hashingAlgorithm;
                switch (_signatureAlgorithm)
                {
                    case SecurityAlgorithms.RsaSha1Signature:
                        hashingAlgorithm = new SHA1CryptoServiceProvider();
                        break;
                    case SecurityAlgorithms.RsaSha256Signature:
                        hashingAlgorithm = new SHA256CryptoServiceProvider();
                        break;
                    default:
                        throw new NotSupportedException("Only SHA1 and SHA256 is supported.");

                }
                return rsaCryptoServiceProvider.SignData(data, hashingAlgorithm);
            }

            var dsaCryptoServiceProvider = _algorithm as DSACryptoServiceProvider;
            if (dsaCryptoServiceProvider != null)
            {
                return dsaCryptoServiceProvider.SignData(data);
            }

            var rsaCng = _algorithm as RSACng;
            if (rsaCng != null)
            {
                return rsaCng.SignData(data);
            }

            throw new NotSupportedException("The given AsymmetricAlgorithm is not supported.");
        }

        public bool CheckSignature(string signedData, byte[] signatureValue)
        {
            var signatureDescription = (SignatureDescription)CryptoConfig.CreateFromName(_signatureAlgorithm);
            var hashAlgorithm = signatureDescription.CreateDigest();
            var hash = hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(signedData));

            var rsa = _algorithm as RSACryptoServiceProvider;
            if (rsa != null)
            {
                return rsa.VerifyHash(hash, signatureDescription.DigestAlgorithm, signatureValue);
            }

            var dsa = _algorithm as DSA;
            if (dsa != null)
            {
                return dsa.VerifySignature(hash, signatureValue);
            }

            throw new NotSupportedException("Only RSA and DSA are supported");
        }

        public void Dispose() => _algorithm.Dispose();
    }
}
