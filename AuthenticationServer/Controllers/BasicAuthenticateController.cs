
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.IO;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Web.Http;
using AuthenticationServer.Extensions;
using Newtonsoft.Json;
using Microsoft.Practices.Unity;
using AuthenticationServer.Configuration;
using AuthenticationServer.Utility.Authentication;
using AuthenticationServer.Utility.Certificate;

namespace AuthenticationServer.Controllers
{
    public class BasicAuthenticateController : ApiController
    {
        private static string DEFAULT_CERTIFICATE_NAME = "Default";
        private readonly AuthenticationServerConfiguration _authenticationServerConfiguration;
        private readonly IAuthenticationHelper _authenticationHelper;

        public BasicAuthenticateController(AuthenticationServerConfiguration authenticationServerConfiguration, IAuthenticationHelper authenticationHelper)
        {
            _authenticationServerConfiguration = authenticationServerConfiguration;
            _authenticationHelper = authenticationHelper;
        }

        // GET: api/Auth
        public HttpResponseMessage Get(string application = null)
        {
            //if not basic Authorization punt
            if(Request.Headers.Authorization == null || Request.Headers.Authorization.Scheme != "Basic")
                throw new HttpResponseException(Request.CreateErrorResponse(System.Net.HttpStatusCode.Unauthorized, "You are unauthorized."));

            //authenticate
            var userNameAndPasword = ExtractUserNameAndPassword(Request.Headers.Authorization.Parameter);
            var username = userNameAndPasword.Item1;
            if (userNameAndPasword == null || !_authenticationHelper.Authenticate(userNameAndPasword.Item1, userNameAndPasword.Item2))
                throw new HttpResponseException(Request.CreateErrorResponse(System.Net.HttpStatusCode.Unauthorized, "You are unauthorized."));

            //assume application is username if not specified
            application = application ?? username;

            //get certificate
            var certAndKeyInfo = CertHelper.GetCertAndKeyInfoFromDisk(_authenticationServerConfiguration.AuthCertificatesRoot, DEFAULT_CERTIFICATE_NAME, true);

            //create signing credentials using the resolved certificate
            var x509SigningCredentials = new X509SigningCredentials(certAndKeyInfo.Certificate);

            //create token
            var jwtSecurityToken = new JwtSecurityToken(
                issuer: "mycompanyauth",
                audience: "mycompany",
                claims: new List<Claim>()
                {
                    new Claim(ClaimTypes.Name, username),
                    //new Claim(ClaimTypes.Role, "AdminRole"),
                    //new Claim(ClaimTypes.UserData, userData)
                },
                notBefore: DateTime.UtcNow.AddMinutes(_authenticationServerConfiguration.AuthTokenNotBeforeAdjustMinutes),
                expires: DateTime.UtcNow.AddMinutes(_authenticationServerConfiguration.AuthTokenExpiryMinutes),
                signingCredentials: x509SigningCredentials
            );

            //create a token handler and use it to write the token to a string
            var tokenHandler = new JwtSecurityTokenHandler();
            string tokenString = tokenHandler.WriteToken(jwtSecurityToken);

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
                Serilog.Log.Error(ex, "Exception in BasicAuthenticateController.ExtractUserNameAndPassword");
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
                Serilog.Log.Error(ex, "Exception in BasicAuthenticateController.ExtractUserNameAndPassword");
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
    }
}
