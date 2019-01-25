using MyLibrary.Crypto.RSA;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Web;

namespace AuthenticationServer.Utility.Certificate
{
    public class CertHelper
    {
        #region Private Members
        private static string DEFAULT_APPLICATION_NAME = "Default";
        #endregion

        #region Public Methods
        public static CertAndKeyInfo GetCertAndKeyInfoFromDisk(string applicationCertificateAndKeyPathRoot, string applicationName, bool fallbackToDefault = false)
        {
            //get certificate locations
            var appCertFiles = GetX509CertKeyPaths(applicationCertificateAndKeyPathRoot, applicationName);

            //get certificate
            string appASCIIArmoredX509Certificate;
            string appASCIIArmoredX509PrivateKey;
            GetX509CertKeyContent(appCertFiles, out appASCIIArmoredX509Certificate, out appASCIIArmoredX509PrivateKey);

            if (string.IsNullOrEmpty(appASCIIArmoredX509Certificate) ||
                string.IsNullOrEmpty(appASCIIArmoredX509PrivateKey))
            {
                if (fallbackToDefault)
                {
                    return GetCertAndKeyInfoFromDisk(applicationCertificateAndKeyPathRoot, DEFAULT_APPLICATION_NAME);
                }
                else
                {
                    return null;
                }
            }
            else
            {
                return GetCertAndKeyInfo(appASCIIArmoredX509Certificate, appASCIIArmoredX509PrivateKey);
            }
        }
        #endregion

        #region Private Methods
        private static CertAndKeyInfo GetCertAndKeyInfo(string asciiArmoredX509Certificate, string asciiArmoredX509PrivateKey)
        {
            //get x509 cert
            var x509Certificate = RSACrypto.GetX509CertificateFromPublicCertificate(asciiArmoredX509Certificate);

            //add private key to certificate so we may use it for authenticate (used for handshake)
            x509Certificate.PrivateKey = RSACrypto.GetRSACryptoServiceProviderFromPrivateKey(asciiArmoredX509PrivateKey);

            return new CertAndKeyInfo(asciiArmoredX509Certificate, asciiArmoredX509PrivateKey, x509Certificate);
        }
        private static string[] GetX509CertKeyPaths(string appCertPathRoot, string applicationName)
        {
            var returnValue = new List<string>();
            if (!string.IsNullOrEmpty(appCertPathRoot))
            {
                var appCertPath = Path.Combine(new string[] { appCertPathRoot, applicationName });
                if (Directory.Exists(appCertPath))
                {
                    returnValue = Directory.GetFiles(appCertPath).ToList();
                }
            }
            return returnValue.ToArray();
        }
        private static void GetX509CertKeyContent(string[] files, out string certificate, out string privateKey)
        {
            certificate = null;
            privateKey = null;

            foreach (var filePath in files)
            {
                var fileContents = File.ReadAllText(filePath);
                if (fileContents.Contains("-----BEGIN CERTIFICATE-----"))
                {
                    certificate = fileContents;
                }
                else if (fileContents.Contains("-----BEGIN RSA PRIVATE KEY-----"))
                {
                    privateKey = fileContents;
                }
                if (!string.IsNullOrEmpty(certificate) && !string.IsNullOrEmpty(privateKey))
                    break;
            }
        } 
        #endregion
    }
}