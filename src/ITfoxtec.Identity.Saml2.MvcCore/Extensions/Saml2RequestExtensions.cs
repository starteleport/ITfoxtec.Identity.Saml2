using System.Threading.Tasks;
using ITfoxtec.Identity.Saml2.Request;
using ITfoxtec.Identity.Saml2.Schemas;
using Microsoft.AspNetCore.Http;

namespace ITfoxtec.Identity.Saml2.MvcCore.Extensions
{
    public static class Saml2RequestExtensions
    {
        /// <summary>
        /// Delete the current Session.
        /// </summary>
        public static async Task<Saml2LogoutRequest> DeleteSession(this Saml2LogoutRequest saml2LogoutRequest, HttpContext httpContext)
        {
            await httpContext.Authentication.SignOutAsync(Saml2Constants.AuthenticationScheme);
            return saml2LogoutRequest;
        }
    }
}
