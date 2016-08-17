using System.IdentityModel.Services;
using ITfoxtec.Identity.Saml2.Request;

namespace ITfoxtec.Identity.Saml2.Mvc.Extensions
{
    public static class Saml2RequestExtensions
    {
        /// <summary>
        /// Delete the current Federated Authentication Session.
        /// </summary>
        public static Saml2LogoutRequest DeleteSession(this Saml2LogoutRequest saml2LogoutRequest)
        {
            FederatedAuthentication.SessionAuthenticationModule.DeleteSessionTokenCookie();
            FederatedAuthentication.SessionAuthenticationModule.SignOut();
            return saml2LogoutRequest;
        }
    }
}
