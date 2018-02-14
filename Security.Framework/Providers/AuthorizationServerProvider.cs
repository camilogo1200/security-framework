using Microsoft.Owin;
using Microsoft.Owin.Security.OAuth;
using System;
using System.Configuration;
using System.Linq;
using System.Threading.Tasks;

namespace Security.Framework.Providers
{
    public class AuthorizationServerProvider : OAuthAuthorizationServerProvider
    {
        /// <summary>
        /// match endpoint is called before Validate Client Authentication. we need
        /// to allow the clients based on domain to enable requests
        /// the header
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public override Task MatchEndpoint(OAuthMatchEndpointContext context)
        {
            SetCORSPolicy(context.OwinContext);
            if (context.Request.Method == "OPTIONS")
            {
                context.RequestCompleted();
                return Task.FromResult(0);
            }
            return base.MatchEndpoint(context);
        }

        /// <summary>
        /// add the allow-origin header only if the origin domain is found on the
        /// allowedOrigin list
        /// </summary>
        /// <param name="context"></param>
        private void SetCORSPolicy(IOwinContext context)
        {
            string allowedUrls = ConfigurationManager.AppSettings["AllowedOrigins"];

            if (!String.IsNullOrWhiteSpace(allowedUrls))
            {
                var list = allowedUrls.Split(',');
                if (list.Length > 0)
                {
                    string origin = context.Request.Headers.Get("Origin");
                    var found = list.Where(item => item == origin).Any();
                    if (found)
                    {
                        context.Response.Headers.Add("Access-Control-Allow-Origin",
                                                     new string[] { origin });
                    }
                }
            }
            context.Response.Headers.Add("Access-Control-Allow-Headers",
                                   new string[] { "Authorization", "Content-Type" });
            context.Response.Headers.Add("Access-Control-Allow-Methods",
                                   new string[] { "OPTIONS", "GET", "POST" });
        }
    }
}