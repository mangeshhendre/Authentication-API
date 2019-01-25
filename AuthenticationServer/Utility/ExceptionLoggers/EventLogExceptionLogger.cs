using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Http.ExceptionHandling;

namespace AuthenticationServer.Utility.ExceptionLoggers
{
    public class EventLogExceptionLogger : ExceptionLogger
    {
        public override void Log(ExceptionLoggerContext context)
        {
            Serilog.Log.Error(context.Exception, "Request: {Request}", context.Request);
        }
    }
}