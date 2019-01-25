using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace AuthenticationTestConsole
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                var executeUri = System.Configuration.ConfigurationManager.AppSettings["ExecuteEndpointSecure"];
                Console.WriteLine("ExecuteEndpointSecure: {0}", executeUri);

                var serviceBusAuthUsername = System.Configuration.ConfigurationManager.AppSettings["AuthUsername"];
                var serviceBusAuthPassword = System.Configuration.ConfigurationManager.AppSettings["AuthPassword"];
                //dynamic utility = new Client(executeUri, "Utility");
                //utility.Username = serviceBusAuthUsername;
                //utility.Password = serviceBusAuthPassword;

                //Console.WriteLine("Executing Utility.Ping (sync)");
                //var result = utility.Ping(delayMilliseconds: 1);
                //Console.WriteLine("PingResponse: {0}", result.PingResponse);

                //Console.WriteLine("Executing Utility.Ping (async)");
                //var asyncResult = utility.AsyncRunner().Ping(delayMilliseconds: 2);
                //Console.WriteLine("PingResponse: {0}", asyncResult.PingResponse);

                //expect this to fail w/ 401
                try
                {
                    Console.WriteLine("Executing Utility.Ping (sync) - Without credentials - Expect Unauthorized (401)");
                    //dynamic utility2 = new Client(executeUri, "Utility");
                    //utility2.Ping();
                }
                catch (WebException webEx)
                {
                    if ((webEx.Response is System.Net.HttpWebResponse) && (webEx.Response as System.Net.HttpWebResponse).StatusCode == System.Net.HttpStatusCode.Unauthorized)
                        Console.WriteLine("Expected Unauthorized: OK");
                    else
                        throw webEx;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("{0}", ex.Message);
                Console.WriteLine("{0}", ex.StackTrace);
            }

            Console.WriteLine("Press any key to continue...");
            Console.ReadKey();
        }
    }
}
