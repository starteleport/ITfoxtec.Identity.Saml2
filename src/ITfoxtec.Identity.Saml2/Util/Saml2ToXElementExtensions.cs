using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Xml.Linq;
using ITfoxtec.Identity.Saml2.Schemas;

namespace ITfoxtec.Identity.Saml2.Util
{
    public static class Saml2ToXElementExtensions
    {
        public static XElement ToXElement(this Saml2NameIdentifier nameId)
        {
            return new XElement(Saml2Constants.AssertionNamespaceX + Saml2Constants.Message.NameId, nameId.Value,
                new XAttribute(Saml2Constants.Message.Format, nameId.Format));
        }

        public static XElement ToXElement(this Saml2Subject subject)
        {
            var items = new XElement[0];
            if (subject.NameId != null)
                items = new[] {subject.NameId.ToXElement()};
            
            var confirmations = subject.SubjectConfirmations.Select(c => c.ToXElement());

            return new XElement(Saml2Constants.AssertionNamespaceX + Saml2Constants.Message.Subject, items.Concat(confirmations));
        }

        public static XElement ToXElement(this Saml2SubjectConfirmation subjectConfirmation)
        {
            var xElement = new XElement(Saml2Constants.AssertionNamespaceX + Saml2Constants.Message.SubjectConfirmation,
                new XAttribute(Saml2Constants.Message.Method, subjectConfirmation.Method.OriginalString));

            if (subjectConfirmation.NameIdentifier != null)
                xElement.Add(subjectConfirmation.NameIdentifier.ToXElement());

            if (subjectConfirmation.SubjectConfirmationData != null)
                xElement.Add(subjectConfirmation.SubjectConfirmationData.ToXElement());

            return xElement;
        }

        public static XElement ToXElement(this Saml2SubjectConfirmationData subjectConfirmationData)
        {
            var dict = new Dictionary<string, object>
            {
                {Saml2Constants.Message.InResponseTo, subjectConfirmationData.InResponseTo?.Value},
                {Saml2Constants.Message.Address, subjectConfirmationData.Address},
                {Saml2Constants.Message.NotBefore, subjectConfirmationData.NotBefore},
                {Saml2Constants.Message.NotOnOrAfter, subjectConfirmationData.NotOnOrAfter},
                {Saml2Constants.Message.Recipient, subjectConfirmationData.Recipient?.OriginalString},
            };

            var attributes = dict.Where(kv => kv.Value != null).Select(kv => new XAttribute(kv.Key, kv.Value));

            return new XElement(Saml2Constants.AssertionNamespaceX + Saml2Constants.Message.SubjectConfirmationData, attributes.ToArray());
        }
    }
}
