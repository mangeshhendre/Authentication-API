using MyLibrary.Crypto.RSA;
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
using AuthenticationServer.Utility.Certificate;
using AuthenticationServer.Configuration;
using System.Net;


namespace AuthenticationServer.Controllers
{
    [RoutePrefix("cache")]
    public class CacheController : ApiController
    {
        private readonly AuthenticationServerConfiguration _authenticationServerConfiguration;

        public CacheController(AuthenticationServerConfiguration authenticationServerConfiguration)
        {
            _authenticationServerConfiguration = authenticationServerConfiguration;
        }

        // GET: api/Auth
        [Route("invalidate/{application?}")]
        [HttpGet]
        public HttpResponseMessage Get(string application = null)
        {
            //authenticated username
            var username = this.RequestContext.Principal.Identity.Name.ToLower();

            //authorize only user "admin" to do this
            if(!username.Equals("admin", StringComparison.OrdinalIgnoreCase))
                throw new HttpResponseException(Request.CreateErrorResponse(HttpStatusCode.Unauthorized, "You are unauthorized."));

            //respond
            return new HttpResponseMessage()
            {
                Content = new StringContent("OK", Encoding.UTF8, "text/html")
            };
        }
    }
}
