using AuthenticationServer.Configuration;
using AuthenticationServer.Utility.Authentication;
using Microsoft.Practices.Unity;
using System;
using Unity;
using Unity.Lifetime;

namespace AuthenticationServer.Utility

{
    class UnityHelper
    {
        private static string APPLICATION_NAME = "AuthenticationServer";

        public static UnityContainer GetContainer()
        {
            try
            {
                UnityContainer container = new UnityContainer();

                //get configuration from etcd
                var authenticationServerConfiguration = new AuthenticationServerConfiguration();

                //configuration
                container.RegisterInstance<AuthenticationServerConfiguration>(authenticationServerConfiguration);

                //authentication
                container.RegisterType<IAuthenticationHelper, AuthenticationHelper>(new ContainerControlledLifetimeManager());

                return container;
            }
            catch (Exception ex)
            {
                Serilog.Log.Error(ex, "Exception in UnityHelper.GetContainer");
                throw;
            }
        }
    }
}