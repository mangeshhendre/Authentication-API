using System;
using System.Collections.Generic;
using System.EnterpriseServices;
using System.Linq;
using System.Web;

namespace AuthenticationServer.Configuration
{
    public class AuthenticationServerConfiguration 
    {
        public string Memcached_Servers { get; set; }
        public string AuthCertificatesRoot { get; set; } = @"F:\Coding\MyRepos\AppCerts";
        public int AuthTokenNotBeforeAdjustMinutes { get; set; }
        public int AuthTokenExpiryMinutes { get; set; }
        public int AuthTokenRefreshNotBeforeAdjustMinutes { get; set; }
        public int AuthTokenRefreshExpiryMinutes { get; set; }
        public int Cache_LocalExpiryMinutes { get; set; }
        public int Cache_MemcachedExpiryMinutes { get; set; }
        public string Cache_HashSalt { get; set; }
    }
}