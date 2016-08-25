﻿using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ITfoxtec.Identity.Saml2.Cryptography;
using ITfoxtec.Identity.Saml2.Http;
using ITfoxtec.Identity.Saml2.Request;
using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2.Util;

namespace ITfoxtec.Identity.Saml2.Bindings
{
    public class Saml2RedirectBinding : Saml2Binding<Saml2RedirectBinding>
    {
        public Uri RedirectLocation { get; protected set; }

        public string Signature { get; protected set; }

        protected override Saml2RedirectBinding BindInternal(Saml2Request saml2RequestResponse, string messageName)
        {
            base.BindInternal(saml2RequestResponse);

            if (saml2RequestResponse.Config.SigningCertificate != null)
            {
                Cryptography.SignatureAlgorithm.ValidateAlgorithm(saml2RequestResponse.Config.SignatureAlgorithm);
                SignatureAlgorithm = saml2RequestResponse.Config.SignatureAlgorithm;
            }

            var requestQueryString = string.Join("&", RequestQueryString(saml2RequestResponse.Config.SigningCertificate, messageName));
            if (saml2RequestResponse.Config.SigningCertificate != null)
            {
                requestQueryString = SigneQueryString(requestQueryString, saml2RequestResponse.Config.SigningCertificate);
            }

            RedirectLocation = new Uri(string.Join("?", saml2RequestResponse.Destination.OriginalString, requestQueryString));

            return this;
        }
        
        private string SigneQueryString(string queryString, X509Certificate2 signingCertificate)
        {
            var saml2Signed = new Saml2SignedText(signingCertificate, SignatureAlgorithm);
            Signature = Convert.ToBase64String(saml2Signed.SignData(Encoding.UTF8.GetBytes(queryString)));

            return string.Join("&", queryString, string.Join("=", Saml2Constants.Message.Signature, Uri.EscapeDataString(Signature)));
        }

        private IEnumerable<string> RequestQueryString(X509Certificate2 signingCertificate, string messageName)
        {
            yield return string.Join("=", messageName, Uri.EscapeDataString(CompressRequest()));

            if (!string.IsNullOrWhiteSpace(RelayState))
            {
                yield return string.Join("=", Saml2Constants.Message.RelayState, Uri.EscapeDataString(RelayState));
            }

            if(signingCertificate != null)
            {
                yield return string.Join("=", Saml2Constants.Message.SigAlg, Uri.EscapeDataString(SignatureAlgorithm));
            }
        }

        private string CompressRequest()
        {
            using (var compressedStream = new MemoryStream())
            using (var deflateStream = new DeflateStream(compressedStream, CompressionLevel.Optimal))
            {
                using (var originalStream = new StreamWriter(deflateStream))
                {
                    originalStream.Write(XmlDocument.OuterXml);
                }

                return Convert.ToBase64String(compressedStream.GetBuffer());
            }
        }

        protected override Saml2Request UnbindInternal(HttpRequest request, Saml2Request saml2RequestResponse, string messageName)
        {
            UnbindInternal(request, saml2RequestResponse);

            if (!"GET".Equals(request.Method, StringComparison.InvariantCultureIgnoreCase))
                throw new InvalidSaml2BindingException("Not HTTP GET Method.");

            if (!request.Query.AllKeys.Contains(messageName))
                throw new Saml2BindingException("HTTP Query String does not contain " + messageName);

            if (saml2RequestResponse.Config.SignatureValidationCertificates != null && saml2RequestResponse.Config.SignatureValidationCertificates.Count() > 0)
            {
                if(!request.Query.AllKeys.Contains(Saml2Constants.Message.Signature))
                    throw new Saml2BindingException("HTTP Query String does not contain " + Saml2Constants.Message.Signature);

                if(!request.Query.AllKeys.Contains(Saml2Constants.Message.SigAlg))
                    throw new Saml2BindingException("HTTP Query String does not contain " + Saml2Constants.Message.SigAlg);
            }

            if (request.Query.AllKeys.Contains(Saml2Constants.Message.RelayState))
            {
                RelayState = request.Query[Saml2Constants.Message.RelayState];
            }

            if (saml2RequestResponse.Config.SignatureValidationCertificates != null && saml2RequestResponse.Config.SignatureValidationCertificates.Count() > 0)
            {
                var actualAignatureAlgorithm = request.Query[Saml2Constants.Message.SigAlg];
                if (saml2RequestResponse.Config.SignatureAlgorithm == null)
                {
                    saml2RequestResponse.Config.SignatureAlgorithm = actualAignatureAlgorithm;
                }
                else if (!saml2RequestResponse.Config.SignatureAlgorithm.Equals(actualAignatureAlgorithm, StringComparison.InvariantCulture))
                {
                    throw new Exception($"Signature Algorithm do not match. Expected algorithm {saml2RequestResponse.Config.SignatureAlgorithm} actual algorithm {actualAignatureAlgorithm}");
                }
                Cryptography.SignatureAlgorithm.ValidateAlgorithm(saml2RequestResponse.Config.SignatureAlgorithm);
                SignatureAlgorithm = saml2RequestResponse.Config.SignatureAlgorithm;

                Signature = request.Query[Saml2Constants.Message.Signature];
                ValidateQueryStringSignature(saml2RequestResponse, request.QueryString, messageName, Convert.FromBase64String(Signature), saml2RequestResponse.Config.SignatureValidationCertificates);
            }

            return Read(request, saml2RequestResponse, messageName, false);
        }

        protected override Saml2Request Read(HttpRequest request, Saml2Request saml2RequestResponse, string messageName, bool validateXmlSignature)
        {
            if (!"GET".Equals(request.Method, StringComparison.InvariantCultureIgnoreCase))
                throw new InvalidSaml2BindingException("Not HTTP GET Method.");

            if (!request.Query.AllKeys.Contains(messageName))
                throw new Saml2BindingException("HTTP Query String does not contain " + messageName);

            saml2RequestResponse.Read(DecompressResponse(request.Query[messageName]), validateXmlSignature);
            XmlDocument = saml2RequestResponse.XmlDocument;
            return saml2RequestResponse;
        }

        private void ValidateQueryStringSignature(Saml2Request saml2RequestResponse, string queryString, string messageName, byte[] signatureValue, IEnumerable<X509Certificate2> signatureValidationCertificates)
        {
            foreach (var signatureValidationCertificate in signatureValidationCertificates)
            {
                saml2RequestResponse.IdentityConfiguration.CertificateValidator.Validate(signatureValidationCertificate);

                var saml2Sign = new Saml2SignedText(signatureValidationCertificate, SignatureAlgorithm);
                if (saml2Sign.CheckSignature(Encoding.UTF8.GetBytes(new RawSaml2QueryString(queryString, messageName).SignedQueryString), signatureValue))
                {
                    // Signature is valid.
                    return;
                }
            }
            throw new Saml2RequestException("Signature is invalid.");
        }

        private string DecompressResponse(string value)
        {
            using (var originalStream = new MemoryStream(Convert.FromBase64String(value)))
            using (var decompressedStream = new MemoryStream())
            {
                using (var deflateStream = new DeflateStream(originalStream, CompressionMode.Decompress))
                {
                    deflateStream.CopyTo(decompressedStream);
                }
                return Encoding.UTF8.GetString(decompressedStream.ToArray());
            }
        }
    }
}
