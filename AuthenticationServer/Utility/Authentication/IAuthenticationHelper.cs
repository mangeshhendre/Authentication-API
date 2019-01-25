using System.IdentityModel.Tokens;

namespace AuthenticationServer.Utility.Authentication
{
    public interface IAuthenticationHelper
    {
        string SigningCertificate { get; set; }
        X509SigningCredentials SigningCredentials { get; set; }

        bool Authenticate(string username, string password);
        bool ValidateAuthorizationToken(string authorization, out string name);
    }
}