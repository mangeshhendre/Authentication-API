using AuthenticationServer.Configuration;
using AuthenticationServer.Utility.Authentication;
using AuthenticationServer.Utility.Certificate;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Web.Http;

namespace AuthenticationServer.Controllers
{
    public class WindowsAuthenticateController : ApiController
    {
        private static string DEFAULT_CERTIFICATE_NAME = "Default";
        private readonly AuthenticationServerConfiguration _authenticationServerConfiguration;
        private readonly IAuthenticationHelper _authenticationHelper;
        private readonly JwtSecurityTokenHandler _jwtSecurityTokenHandler;

        public WindowsAuthenticateController(AuthenticationServerConfiguration authenticationServerConfiguration, IAuthenticationHelper authenticationHelper)
        {
            _authenticationServerConfiguration = authenticationServerConfiguration;
            _authenticationHelper = authenticationHelper;
            _jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
        }

        // GET: api/Auth
        public HttpResponseMessage Get(string application = null)
        {
            var expiration = DateTime.UtcNow.AddMinutes(_authenticationServerConfiguration.AuthTokenExpiryMinutes);

            //assume we could have domain\user
            var identityNameParts = RequestContext.Principal.Identity.Name.Split('\\');
            var nameClaimValue = identityNameParts.Length == 1 ? identityNameParts [0] : string.Format("{0}@{1}", identityNameParts[1], identityNameParts[0]);

            //create token
            var jwtSecurityToken = new JwtSecurityToken(
                issuer: "mycompanyauth",
                audience: "mycompany",
                claims: new List<Claim>()
                {
                    new Claim(ClaimTypes.Name, nameClaimValue),
                    //new Claim(ClaimTypes.Role, "AdminRole"),
                    //new Claim(ClaimTypes.UserData, userData)
                },
                notBefore: DateTime.UtcNow.AddMinutes(_authenticationServerConfiguration.AuthTokenNotBeforeAdjustMinutes),
                expires: expiration,
                signingCredentials: _authenticationHelper.SigningCredentials
            );

            //create a token handler and use it to write the token to a string
            string tokenString = _jwtSecurityTokenHandler.WriteToken(jwtSecurityToken);

            //create cookie
            var cookie = new CookieHeaderValue("Bearer", tokenString);
            cookie.HttpOnly = true;
            cookie.Secure = true;
            cookie.Expires = expiration;
            cookie.Domain = TrimStart(Request.RequestUri.Host, "authentication");
            cookie.Path = "/";

            //get redirect location
            IEnumerable<string> refererValues;
            Request.Headers.TryGetValues("Referer", out refererValues);

            //respond
            if (refererValues != null && refererValues.Count() > 0)
            {
                var response = Request.CreateResponse(HttpStatusCode.Found);
                response.Headers.Location = new Uri(refererValues.First());
                response.Headers.AddCookies(new CookieHeaderValue[] { cookie });
                return response;
            }

            //respond
            return new HttpResponseMessage()
            {
                Content = new StringContent(tokenString, Encoding.UTF8, "text/html")
            };
        }

        private static Tuple<string, string> ExtractUserNameAndPassword(string authorizationParameter)
        {
            byte[] credentialBytes;

            try
            {
                credentialBytes = Convert.FromBase64String(authorizationParameter);
            }
            catch (FormatException ex)
            {
                Serilog.Log.Error(ex, "Exception in WindowsAuthenticateController.ExtractUserNameAndPassword");
                return null;
            }

            // The currently approved HTTP 1.1 specification says characters here are ISO-8859-1.
            // However, the current draft updated specification for HTTP 1.1 indicates this encoding is infrequently
            // used in practice and defines behavior only for ASCII.
            Encoding encoding = Encoding.ASCII;
            // Make a writable copy of the encoding to enable setting a decoder fallback.
            encoding = (Encoding)encoding.Clone();
            // Fail on invalid bytes rather than silently replacing and continuing.
            encoding.DecoderFallback = DecoderFallback.ExceptionFallback;
            string decodedCredentials;

            try
            {
                decodedCredentials = encoding.GetString(credentialBytes);
            }
            catch (DecoderFallbackException ex)
            {
                Serilog.Log.Error(ex, "Exception in WindowsAuthenticateController.ExtractUserNameAndPassword");
                return null;
            }

            if (String.IsNullOrEmpty(decodedCredentials))
            {
                return null;
            }

            int colonIndex = decodedCredentials.IndexOf(':');

            if (colonIndex == -1)
            {
                return null;
            }

            string userName = decodedCredentials.Substring(0, colonIndex);
            string password = decodedCredentials.Substring(colonIndex + 1);
            return new Tuple<string, string>(userName, password);
        }

        private static string TrimStart(string sourceString, string value)
        {
            int index = sourceString.IndexOf(value);
            return index < 0
                ? sourceString
                : sourceString.Remove(index, value.Length);
        }
    }
}
