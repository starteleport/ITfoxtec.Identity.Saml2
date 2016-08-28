using System.Xml;
using ITfoxtec.Identity.Saml2.Util;

namespace ITfoxtec.Identity.Saml2.Extensions
{
    /// <summary>
    /// Extension methods for XmlAttribute
    /// </summary>
    internal static class XmlAttributeExtensions
    {
        public static T GetValueOrNull<T>(this XmlAttribute xmlAttribute)
        {
            return GenericTypeConverter.ConvertValue<T>(xmlAttribute?.Value, xmlAttribute);
        }
    }
}
