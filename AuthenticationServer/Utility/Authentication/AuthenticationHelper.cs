using Microsoft.Practices.Unity;
using AuthenticationServer.Configuration;
using AuthenticationServer.Utility.Certificate;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Linq;
using System.Web.Http;
using MyLibrary.Crypto.RSA;

namespace AuthenticationServer.Utility.Authentication
{
    public class AuthenticationHelper : IAuthenticationHelper
    {
        #region Private Members
        private static string DEFAULT_CERTIFICATE_NAME = "Default";

        private readonly AuthenticationServerConfiguration _authenticationServerConfiguration;
        private readonly object _passwordHashLock;
        private readonly SHA256Managed _sha250Managed;
        private readonly TimeSpan? _memcachedExpiryTimeSpan;

        private readonly JwtSecurityTokenHandler _jwtSecurityTokenHandler;
        private string _signingCertificate;
        private TokenValidationParameters _tokenValidationParameters;
        #endregion

        #region Constructors
        public AuthenticationHelper(AuthenticationServerConfiguration authenticationServerConfiguration)
        {
            _authenticationServerConfiguration = authenticationServerConfiguration;

            _passwordHashLock = new object();
            _sha250Managed = new SHA256Managed();

            _memcachedExpiryTimeSpan = _authenticationServerConfiguration.Cache_MemcachedExpiryMinutes > 0 ? (TimeSpan?)TimeSpan.FromMinutes(_authenticationServerConfiguration.Cache_MemcachedExpiryMinutes) : null;

            _jwtSecurityTokenHandler = new JwtSecurityTokenHandler();

            var certAndKeyInfo = CertHelper.GetCertAndKeyInfoFromDisk(_authenticationServerConfiguration.AuthCertificatesRoot, DEFAULT_CERTIFICATE_NAME, true);
            SigningCertificate = certAndKeyInfo.AppASCIIArmoredX509Certificate;
            SigningCredentials = new X509SigningCredentials(certAndKeyInfo.Certificate);

        }
        #endregion

        #region Properties
        public X509SigningCredentials SigningCredentials { get; set; }
        public string SigningCertificate
        {
            get
            {
                return _signingCertificate;
            }
            set
            {
                if (!value.Equals(_signingCertificate))
                {
                    _signingCertificate = value;

                    var x509CertificatePublic = RSACrypto.GetX509CertificateFromPublicCertificate(_signingCertificate);
                    var x509SecurityToken = new X509SecurityToken(x509CertificatePublic);

                    _tokenValidationParameters = new TokenValidationParameters()
                    {
                        ValidIssuer = "mycompanyauth",
                        ValidAudiences = new List<string> { "mycompany" },
                        IssuerSigningToken = x509SecurityToken,
                        RequireExpirationTime = true
                    };
                }
            }
        }
        #endregion

        #region Public Methods
        public bool Authenticate(string username, string password)
        {
            try
            {
                //normalize username
                username = username.ToLower();

                var currentPassword = "Password1"; //get password from somewhere

                var hashGetResult = GetHash(_authenticationServerConfiguration.Cache_HashSalt + currentPassword); 

                //hash attempted password and check if hash matches
                return GetHash(_authenticationServerConfiguration.Cache_HashSalt + password).Equals(hashGetResult);
            }
            catch (Exception ex)
            {
                Serilog.Log.Error(ex, "Exception in AuthenticationHelper.Authenticate - Username: {username} - Password: {password}", username, password);
                return false;
            }
        }

        public bool ValidateAuthorizationToken(string authorization, out string name)
        {
            try
            {
                //validate the token is signed
                SecurityToken secToken;
                ClaimsPrincipal claimsPrincipal = _jwtSecurityTokenHandler.ValidateToken(authorization, _tokenValidationParameters, out secToken);

                //validate token lifetime
                var utcNow = DateTime.UtcNow;
                if (utcNow < secToken.ValidFrom || utcNow > secToken.ValidTo)
                {
                    var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
                    var nowEpoch = (utcNow - epoch).TotalSeconds;
                    throw new SecurityTokenExpiredException(string.Format("Token has expired. - utc now: {0}", nowEpoch));
                }

                var nameClaim = claimsPrincipal.Claims.FirstOrDefault(c => c.Type.Equals(ClaimTypes.Name));
                if (nameClaim != null)
                {
                    name = nameClaim.Value;
                    return true;
                }
                else
                {
                    //_logger.Error("AuthorizationHelper.ValidateAuthorizationToken - Authorization Token missing claim - http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", null, new Dictionary<string, string> { { "JWT", authorization } });
                    name = null;
                    return false;
                }
            }
            catch (Exception ex)
            {
                Serilog.Log.Error(ex, "Exception in AuthenticationHelper.ValidateAuthorizationToken");

                name = null;
                return false;
            }
        }
        #endregion

        #region Private Methods
        private string GetHash(string value)
        {
            byte[] hashBytes = null;
            lock (_passwordHashLock)
            {
                hashBytes = _sha250Managed.ComputeHash(System.Text.Encoding.UTF8.GetBytes(value));
            }

            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < hashBytes.Length; i++)
            {
                sb.Append(hashBytes[i].ToString("X2"));
            }
            return sb.ToString();

        }
        #endregion
    }
}