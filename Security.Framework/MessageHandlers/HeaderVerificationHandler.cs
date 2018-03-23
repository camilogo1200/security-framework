using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http;

namespace Security.Framework.MessageHandlers
{
    public class HeaderVerificationHandler : DelegatingHandler
    {
        protected async override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Debug.WriteLine("[SignaturesMessageHandler] - Process request");
            bool isValidRequestHeaders = ValidateRequestHeaders(request);
            if (!isValidRequestHeaders)
            {
                var notAuthResponse = new HttpResponseMessage(HttpStatusCode.Unauthorized)
                {
                    Content = new StringContent("Not Authorized. VRH")
                };
                var tsc = new TaskCompletionSource<HttpResponseMessage>();
                tsc.SetResult(notAuthResponse);
                return await tsc.Task;
            }
            var response = await base.SendAsync(request, cancellationToken);
            Debug.WriteLine("[SignaturesMessageHandler] - ProcesResponse ");

            //Add Secure Headers
            return response;
        }

        private bool ValidateRequestHeaders(HttpRequestMessage request)
        {
            if (request.Method.Equals(HttpMethod.Options))
            {
                return true;
            }
            HttpRequestHeaders headers = request.Headers;
            HttpMethod method = request.Method;
            //load Headers in request
            ICollection<string> lHeaderList = new List<string>();

            string appSignature = Properties.Messages.Header_X_APP_SIGNATURE.ToString();

            if (String.IsNullOrEmpty(appSignature))
            {
                System.IO.File.WriteAllText(@"C:\Seguridad\ErrorSeguridad.txt", "Propiedad Header_X_APP_SIGNATURE no encontrada en archivo de propiedades (.resx)", Encoding.UTF8);
                throw new ObjectNotFoundException("Propiedad Header_X_APP_SIGNATURE no encontrada en archivo de propiedades (.resx)");
            }

            string machineSignature = Properties.Messages.Header_MACHINE_AUTHENTICATION.ToString();
            if (String.IsNullOrEmpty(machineSignature))
            {
                System.IO.File.WriteAllText(@"C:\Seguridad\ErrorSeguridad.txt", "Propiedad Header_CONTENT_SHA3 no encontrada en archivo de propiedades (.resx)", Encoding.UTF8);
                throw new ObjectNotFoundException("Propiedad Header_MACHINE_AUTHENTICATION no encontrada en archivo de propiedades (.resx)");
            }

            string contentSha3Header = Properties.Messages.Header_CONTENT_SHA3.ToString();
            if (String.IsNullOrEmpty(contentSha3Header))
            {
                System.IO.File.WriteAllText(@"C:\Seguridad\ErrorSeguridad.txt", "Propiedad Header_CONTENT_SHA3 no encontrada en archivo de propiedades (.resx)", Encoding.UTF8);
                throw new ObjectNotFoundException("Propiedad Header_CONTENT_SHA3 no encontrada en archivo de propiedades (.resx)");
            }

            string bearerTokenHeader = Properties.Messages.Header_BEARERTOKEN.ToString();
            if (String.IsNullOrEmpty(bearerTokenHeader))
            {
                System.IO.File.WriteAllText(@"C:\Seguridad\ErrorSeguridad.txt", "Propiedad Header_BEARERTOKEN no encontrada en archivo de propiedades (.resx)", Encoding.UTF8);
                throw new ObjectNotFoundException("Propiedad Header_BEARERTOKEN no encontrada en archivo de propiedades (.resx)");
            }

            lHeaderList.Add(appSignature);
            lHeaderList.Add(machineSignature);

            foreach (string header in lHeaderList)
            {
                if (!headers.Contains(header))
                {
                    System.IO.File.WriteAllText(@"C:\Seguridad\ErrorSeguridad.txt", header + " not found", Encoding.UTF8);
                    throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.BadRequest)
                    {
                        Content = new StringContent(header + " not found")
                    });
                    return false;
                }
            }

            if ((method.Equals(HttpMethod.Post)
                            || method.Equals(HttpMethod.Put)
                            || method.Equals(HttpMethod.Delete)) && !headers.Contains(contentSha3Header))
            {
                System.IO.File.WriteAllText(@"C:\Seguridad\ErrorSeguridad.txt", method.ToString(), Encoding.UTF8);
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.BadRequest)
                {
                    Content = new StringContent(method + " not found")
                });
                return false;
            }
            return true;
        }
    }
}