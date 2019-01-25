using AuthenticationServer.Utility;
using AuthenticationServer.Utility.ExceptionLoggers;
using Serilog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.Http;
using System.Web.Http.ExceptionHandling;
using System.Web.Http.Filters;

namespace AuthenticationServer
{
    public static class WebApiConfig
    {
        public static void Register(HttpConfiguration config)
        {
            // Web API configuration and services
            config.Services.Add(typeof(IExceptionLogger), new EventLogExceptionLogger());

            // Web API routes
            config.MapHttpAttributeRoutes();

            config.Routes.MapHttpRoute(
                name: "AuthenticateApi",
                routeTemplate: "{controller}/{application}",
                defaults: new { controller = "Authenticate", action="Get", application = RouteParameter.Optional }
            );

            //get an instance of the unity container with all dependencies registered
            var container = UnityHelper.GetContainer();

            //register unity as dependency resolver
            config.DependencyResolver = new UnityResolver(container);

            //Serilog
            Log.Logger = new LoggerConfiguration()
                .WriteTo.EventLog("Authentication API", manageEventSource: true)
                .CreateLogger();
        }
    }
}
