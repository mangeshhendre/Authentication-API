using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Web;

namespace AuthenticationServer.Utility.Certificate
{
    public class CertAndKeyInfo
    {
        #region Private Members
        private readonly string _asciiArmoredX509Certificate;
        private readonly string _asciiArmoredX509PrivateKey;
        private readonly X509Certificate2 _certificate;
        #endregion

        #region Constructors
        private CertAndKeyInfo() { }
        public CertAndKeyInfo(string appASCIIArmoredX509Certificate, string appASCIIArmoredX509PrivateKey, X509Certificate2 certificate)
        {
            _asciiArmoredX509Certificate = appASCIIArmoredX509Certificate;
            _asciiArmoredX509PrivateKey = appASCIIArmoredX509PrivateKey;
            _certificate = certificate;
        }
        #endregion

        #region Public Properties
        public string AppASCIIArmoredX509Certificate { get { return _asciiArmoredX509Certificate; } }
        public string AppASCIIArmoredX509PrivateKey { get { return _asciiArmoredX509PrivateKey; } }
        public X509Certificate2 Certificate { get { return _certificate; } }
        #endregion
    }
}