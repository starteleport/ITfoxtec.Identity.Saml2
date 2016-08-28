using System;
using System.Web;

namespace ITfoxtec.Identity.Saml2.Mvc.Extensions
{
    /// <summary>
    /// Extension methods for HttpRequest
    /// </summary>
    public static class HttpRequestExtensions
    {
        /// <summary>
        /// Converts a System.Web.HttpRequestBase to ITfoxtec.Identity.Saml2.Http.HttpRequest.
        /// </summary>
        public static Http.HttpRequest ToGenericHttpRequest(this HttpRequestBase request)
        {
            return new Http.HttpRequest
            {
                Method = request.HttpMethod,
                QueryString = request.Url.Query,
                Query = request.QueryString,
                Form = "POST".Equals(request.HttpMethod, StringComparison.InvariantCultureIgnoreCase) ? request.Form : null,
            };
        }
    }
}
