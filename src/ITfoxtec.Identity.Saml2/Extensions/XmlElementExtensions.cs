using System.Xml;
using ITfoxtec.Identity.Saml2.Util;

namespace ITfoxtec.Identity.Saml2.Extensions
{
    /// <summary>
    /// Extension methods for XmlElement
    /// </summary>
    internal static class XmlElementExtensions
    {
        public static T GetValueOrNull<T>(this XmlElement xmlElement)
        {
            return GenericTypeConverter.ConvertValue<T>(xmlElement?.InnerText?.Trim(), xmlElement);
        }
    }
}
