using System;
using System.Data;
using System.Net.Http;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;

namespace Security.Framework.Filters
{
    public class RequireHttpsAttribute : AuthorizationFilterAttribute
    {
        public override void OnAuthorization(HttpActionContext actionContext)
        {
            if (actionContext.Request.RequestUri.Scheme != Uri.UriSchemeHttps)
            {
                string msgRequiredHttps = Properties.Messages.MSG_HTTP_REQUIRED.ToString();
                if (String.IsNullOrEmpty(msgRequiredHttps))
                {
                    throw new ObjectNotFoundException("Propiedad MSG_HTTP_REQUIRED no encontrada en archivo de propiedades (.resx)");
                }
                actionContext.Response = new HttpResponseMessage(System.Net.HttpStatusCode.Forbidden)
                {
                    ReasonPhrase = msgRequiredHttps
                };
            }
            else
            {
                base.OnAuthorization(actionContext);
            }
        }
    }
}