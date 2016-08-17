﻿using System;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Xml;
using ITfoxtec.Identity.Saml2.Cryptography;
using ITfoxtec.Identity.Saml2.Http;
using ITfoxtec.Identity.Saml2.Request;
using ITfoxtec.Identity.Saml2.Schemas;
using Security.Cryptography;
using Security.Cryptography.X509Certificates;

namespace ITfoxtec.Identity.Saml2.Bindings
{
    public abstract class Saml2Binding<T>
    {
        public XmlDocument XmlDocument { get; protected set; }

        public string SignatureAlgorithm { get; protected set; }

        /// <summary>
        /// <para>Sets the relaystate of the message.</para>
        /// <para>If the message being built is a response message, the relaystate will be included unmodified.</para>
        /// <para>If the message being built is a request message, the relaystate will be encoded and compressed before being included.</para>
        /// </summary>
        public string RelayState { get; set; }

        public Saml2Binding()
        { }

        public T Bind(Saml2Request saml2Request)
        {
            return BindInternal(saml2Request, Saml2Constants.Message.SamlRequest);
        }

        public T Bind(Saml2Response saml2Response)
        {
            return BindInternal(saml2Response, Saml2Constants.Message.SamlResponse);
        }

        protected virtual Saml2Binding<T> BindInternal(Saml2Request saml2RequestResponse)
        {
            if (saml2RequestResponse == null)
                throw new ArgumentNullException(nameof(saml2RequestResponse));

            if (saml2RequestResponse.Config == null)
                throw new ArgumentNullException("saml2RequestResponse.Config");

            var signingCertificate = saml2RequestResponse.Config.SigningCertificate;
            if (signingCertificate != null)
            {
                if (signingCertificate.HasCngKey())
                {
                    var privateKey = signingCertificate.GetCngPrivateKey();
                    if (privateKey == null)
                    {
                        throw new ArgumentException("No Private Key present in Signing Certificate or missing private key read credentials.");
                    }

                    if (privateKey.Algorithm.Algorithm != "RSA")
                    {
                        throw new ArgumentException("The Private Key present in Signing Certificate must be RSA.");
                    }
                }
                else
                {
                    if (signingCertificate.PrivateKey == null)
                    {
                        throw new ArgumentException("No Private Key present in Signing Certificate or missing private key read credentials.");
                    }

                    if (!(signingCertificate.PrivateKey is DSA || signingCertificate.PrivateKey is RSACryptoServiceProvider))
                    {
                        throw new ArgumentException("The Private Key present in Signing Certificate must be either DSA or RSACryptoServiceProvider.");
                    }
                }
            }

            XmlDocument = saml2RequestResponse.ToXml();

#if DEBUG
            Debug.WriteLine("Saml2P: " + XmlDocument.OuterXml);
#endif
            return this;
        }

        protected abstract T BindInternal(Saml2Request saml2RequestResponse, string messageName);

        public Saml2Request Unbind(HttpRequest request, Saml2Request saml2Request)
        {
            return UnbindInternal(request, saml2Request, Saml2Constants.Message.SamlRequest);
        }

        public Saml2Response Unbind(HttpRequest request, Saml2Response saml2Response)
        {
            return UnbindInternal(request, saml2Response, Saml2Constants.Message.SamlResponse) as Saml2Response;
        }

        protected Saml2Request UnbindInternal(HttpRequest request, Saml2Request saml2RequestResponse)
        {
            if (request == null)
                throw new ArgumentNullException(nameof(request));

            if (saml2RequestResponse == null)
                throw new ArgumentNullException(nameof(saml2RequestResponse));

            if (saml2RequestResponse.Config == null)
                throw new ArgumentNullException("saml2RequestResponse.Config");

            var certificates = saml2RequestResponse.SignatureValidationCertificates;

            if (certificates == null || !certificates.Any())
                saml2RequestResponse.SignatureValidationCertificates = saml2RequestResponse.Config.SignatureValidationCertificates;

            if (saml2RequestResponse.SignatureAlgorithm == null)
                saml2RequestResponse.SignatureAlgorithm = saml2RequestResponse.Config.SignatureAlgorithm;

            if (certificates != null && certificates.Count(c => c.PublicKey == null) > 0)
                throw new ArgumentException("No Public Key present in at least Signature Validation Certificate.");

            return saml2RequestResponse;
        }

        protected abstract Saml2Request UnbindInternal(HttpRequest request, Saml2Request saml2RequestResponse, string messageName);

        public Saml2Request ReadSamlRequest(HttpRequest request, Saml2Request saml2Request)
        {
            return Read(request, saml2Request, Saml2Constants.Message.SamlRequest, false);
        }

        public Saml2Request ReadSamlResponse(HttpRequest request, Saml2Response saml2Response)
        {
            return Read(request, saml2Response, Saml2Constants.Message.SamlResponse, false);
        }

        protected abstract Saml2Request Read(HttpRequest request, Saml2Request saml2RequestResponse, string messageName, bool validateXmlSignature);
    }
}
