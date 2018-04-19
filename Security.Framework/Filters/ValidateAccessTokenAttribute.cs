using System;
using System.Collections.Generic;
using System.Linq;
using System.Data;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Http;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;


namespace Security.Framework.Filters
{
    public class ValidateAccessTokenAttribute : ActionFilterAttribute
    {
        public override void OnActionExecuting(HttpActionContext filterContext)
        {
            
            string msgRequiredHttps = "Access token invalido!";
            if (!ValidateAccessToken(filterContext.Request))               
            {
                filterContext.Response = new HttpResponseMessage(System.Net.HttpStatusCode.Forbidden)
                {
                    ReasonPhrase = msgRequiredHttps
                };
            }
        }

        private bool ValidateAccessToken(HttpRequestMessage message)
        {
            string accessToken = Properties.Messages.Header_ACCESS_TOKEN.ToString();
            IEnumerable<string> values;
            if (String.IsNullOrEmpty(accessToken))
            {
                throw new ObjectNotFoundException("Propiedad Header_ACCESS_TOKEN no encontrada en archivo de propiedades (.resx)");
            }
            if (message.Headers.TryGetValues(accessToken, out values))
            {
                string header = values.FirstOrDefault();
                return (!String.IsNullOrEmpty(header));

                //TODO: IR A VALIDAR EN BD
            }

            return false;
        }
    }
}
