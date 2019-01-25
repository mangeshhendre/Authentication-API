using AuthenticationServer.Configuration;
using AuthenticationServer.Utility.Authentication;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Web.Http;
using System.Linq;
using System.Text;

namespace AuthenticationServer.Controllers
{
    public class JWTAuthenticateController : ApiController
    {
        private static string DEFAULT_CERTIFICATE_NAME = "Default";
        private readonly AuthenticationServerConfiguration _authenticationServerConfiguration;
        private readonly IAuthenticationHelper _authenticationHelper;
        private readonly JwtSecurityTokenHandler _jwtSecurityTokenHandler;

        public JWTAuthenticateController(AuthenticationServerConfiguration authenticationServerConfiguration, IAuthenticationHelper authenticationHelper)
        {
            _authenticationServerConfiguration = authenticationServerConfiguration;
            _authenticationHelper = authenticationHelper;
            _jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
        }

        // GET: api/Auth
        public HttpResponseMessage Get(bool refresh = true)
        {
            //if not JWT Authorization punt
            if(Request.Headers.Authorization == null || Request.Headers.Authorization.Scheme != "Bearer")
                throw new HttpResponseException(Request.CreateErrorResponse(System.Net.HttpStatusCode.Unauthorized, "You are unauthorized."));

            //get token
            var authorizationToken = Request.Headers.Authorization.Parameter;

            //validate token and get username
            string username = null;
            if(!_authenticationHelper.ValidateAuthorizationToken(authorizationToken, out username))
                throw new HttpResponseException(Request.CreateErrorResponse(System.Net.HttpStatusCode.Unauthorized, "You are unauthorized."));

            if (!refresh)
                return new HttpResponseMessage { StatusCode = HttpStatusCode.OK };

            //create new token
            var jwtSecurityToken = new JwtSecurityToken(
                issuer: "mycompanyauth",
                audience: "mycompany",
                claims: new List<Claim>()
                {
                    new Claim(ClaimTypes.Name, username),
                },
                notBefore: DateTime.UtcNow.AddMinutes(_authenticationServerConfiguration.AuthTokenRefreshNotBeforeAdjustMinutes),
                expires: DateTime.UtcNow.AddMinutes(_authenticationServerConfiguration.AuthTokenRefreshExpiryMinutes),
                signingCredentials: _authenticationHelper.SigningCredentials
            );

            //create a token handler and use it to write the token to a string
            string tokenString = _jwtSecurityTokenHandler.WriteToken(jwtSecurityToken);
            
            //respond
            return new HttpResponseMessage
            {
                Content = new StringContent(tokenString, Encoding.UTF8, "text/html")
            };
        }
    }
}
