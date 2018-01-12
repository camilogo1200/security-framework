using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;

namespace Security.Framework.MessageHandlers
{
    public class SignaturesMessageHandler : DelegatingHandler
    {
        protected async override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Debug.WriteLine("[SignaturesMessageHandler] - Process request");
            bool isValidRequestHeaders = ValidateRequestHeaders(request);
            if (!isValidRequestHeaders)
            {
                var notAuthResponse = new HttpResponseMessage(HttpStatusCode.Unauthorized)
                {
                    Content = new StringContent("Not Authorized.")
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
            HttpRequestHeaders headers = request.Headers;
            HttpMethod method = request.Method;
            //load Headers in request
            ICollection<string> lHeaderList = new List<string>();

            string appSignature = Properties.Messages.Header_X_APP_SIGNATURE.ToString();
            string machineSignature = Properties.Messages.Header_MACHINE_AUTHENTICATION.ToString();

            lHeaderList.Add(appSignature);
            lHeaderList.Add(machineSignature);

            foreach (string header in lHeaderList)
            {
                if (!headers.Contains(header))
                {
                    return false;
                }
            }

            if ((method.Equals(HttpMethod.Post)
                            || method.Equals(HttpMethod.Put)
                            || method.Equals(HttpMethod.Delete)) && !headers.Contains("Content-SHA3"))
            {
                return false;
            }
            return true;
        }
    }
}