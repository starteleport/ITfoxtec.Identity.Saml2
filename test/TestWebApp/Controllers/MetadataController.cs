﻿using ITfoxtec.Identity.Saml2.Configuration;
using ITfoxtec.Identity.Saml2.Mvc.Extensions;
using ITfoxtec.Identity.Saml2.Request;
using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Web.Mvc;
using ITfoxtec.Identity.Saml2.Configuration;
using ITfoxtec.Identity.Saml2.Mvc.Extensions;
using ITfoxtec.Identity.Saml2.Request;

namespace TestWebApp.Controllers
{
    [AllowAnonymous]
    public class MetadataController : Controller
    {
        private const string defaultSite = "http://localhost:3112/";
        private readonly Saml2Configuration config;

        public MetadataController()
        {
            config = IdentityConfig.Saml2Configuration;
        }

        public ActionResult Index()
        {
            var entityDescriptor = new EntityDescriptor(config);
            entityDescriptor.ValidUntil = 365;
            entityDescriptor.SPSsoDescriptor = new SPSsoDescriptor
            {
                WantAssertionsSigned = true,
                SigningCertificates = new X509Certificate2[]
                {
                    config.SigningCertificate
                },
                //EncryptionCertificates = new X509Certificate2[]
                //{
                //    config.DecryptionCertificate
                //},
                SingleLogoutServices = new SingleLogoutService[]
                {
                    new SingleLogoutService { Binding = ProtocolBindings.HttpPost, Location = new Uri($"{defaultSite}/Auth/SingleLogout"), ResponseLocation = new Uri($"{defaultSite}/Auth/LoggedOut") }
                },
                NameIDFormats = new Uri[] { NameIdentifierFormats.X509SubjectName },
                AssertionConsumerServices = new AssertionConsumerService[]
                {
                    new AssertionConsumerService {  Binding = ProtocolBindings.HttpPost, Location = new Uri($"{defaultSite}/Auth/AssertionConsumerService") }
                },
                AttributeConsumingServices = new AttributeConsumingService[] 
                {
                    new AttributeConsumingService { ServiceName = new ServiceName("Some SP", "en"), RequestedAttributes = CreateRequestedAttributes() }
                },
            };
            entityDescriptor.ContactPerson = new ContactPerson(ContactTypes.Administrative)
            {
                Company = "Some Company",
                GivenName = "Some Given Name",
                SurName = "Some Sur Name",
                EmailAddress = "some@some-domain.com",
                TelephoneNumber = "11111111",
            };
            return new Saml2Metadata(entityDescriptor).CreateMetadata().ToActionResult();
        }

        private IEnumerable<RequestedAttribute> CreateRequestedAttributes()
        {
            yield return new RequestedAttribute("urn:oid:2.5.4.4");
            yield return new RequestedAttribute("urn:oid:2.5.4.3", false);
        }
    }
}