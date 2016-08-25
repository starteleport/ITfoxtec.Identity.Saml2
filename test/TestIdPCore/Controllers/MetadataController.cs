﻿using System;
using System.Security.Cryptography.X509Certificates;
using ITfoxtec.Identity.Saml2.Configuration;
using ITfoxtec.Identity.Saml2.MvcCore.Extensions;
using ITfoxtec.Identity.Saml2.Request;
using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace TestIdPCore.Controllers
{
    [AllowAnonymous]
    [Route("Metadata")]
    public class MetadataController : Controller
    {
        private readonly Saml2Configuration config;

        public MetadataController(Saml2Configuration config)
        {
            this.config = config;
        }

        public IActionResult Index()
        {
            var entityDescriptor = new EntityDescriptor(config);
            entityDescriptor.ValidUntil = 365;
            entityDescriptor.IdPSsoDescriptor = new IdPSsoDescriptor
            {
                SigningCertificates = new X509Certificate2[]
                {
                    config.SigningCertificate
                },
                //EncryptionCertificates = new X509Certificate2[]
                //{
                //    config.DecryptionCertificate
                //},
                SingleSignOnServices = new SingleSignOnService[]
                {
                    new SingleSignOnService { Binding = ProtocolBindings.HttpRedirect, Location = config.SingleSignOnDestination }
                },
                SingleLogoutServices = new SingleLogoutService[]
                {
                    new SingleLogoutService { Binding = ProtocolBindings.HttpPost, Location = config.SingleLogoutDestination }
                },
                NameIDFormats = new Uri[] { NameIdentifierFormats.X509SubjectName },
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
    }
}