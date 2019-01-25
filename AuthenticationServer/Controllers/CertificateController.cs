using AuthenticationServer.Configuration;
using AuthenticationServer.Utility.Certificate;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Web.Http;

namespace AuthenticationServer.Controllers
{
    [RoutePrefix("Certificate")]
    public class CertificateController : ApiController
    {
        private static string DEFAULT_CERTIFICATE_NAME = "Default";
        private readonly AuthenticationServerConfiguration _authenticationServerConfiguration;

        public CertificateController(AuthenticationServerConfiguration authenticationServerConfiguration)
        {
            _authenticationServerConfiguration = authenticationServerConfiguration;
        }

        // GET: api/Cert/Test
        [Route("{name?}")]
        [HttpGet]
        public HttpResponseMessage Get(string name = null)
        {
            var certAndKeyInfo = CertHelper.GetCertAndKeyInfoFromDisk(_authenticationServerConfiguration.AuthCertificatesRoot, name ?? DEFAULT_CERTIFICATE_NAME, true);
            var publicCert = certAndKeyInfo.AppASCIIArmoredX509Certificate;//.Replace("\r\n", string.Empty);

            return new HttpResponseMessage()
            {
                Content = new StringContent(publicCert, Encoding.UTF8, "text/html")
            };
        }
    }
}
