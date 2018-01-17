using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Security.Framework.MessageHandlers
{
    public class ApiKeyHandler : DelegatingHandler
    {
        public string Key { get; set; }

        public ApiKeyHandler(string key)
        {
            this.Key = key;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Debug.WriteLine("[ApiKeyHandler]");
            if (!ValidateKey(request))
            {
                var response = new HttpResponseMessage(HttpStatusCode.Forbidden);
                var tsc = new TaskCompletionSource<HttpResponseMessage>();
                tsc.SetResult(response);
                return tsc.Task;
            }
            return base.SendAsync(request, cancellationToken);
        }

        private bool ValidateKey(HttpRequestMessage message)
        {
            string appSignature = Properties.Messages.Header_X_APP_SIGNATURE.ToString();

            if (String.IsNullOrEmpty(appSignature))
            {
                throw new ObjectNotFoundException("Propiedad Header_X_APP_SIGNATURE no encontrada en archivo de propiedades (.resx)");
            }
            if (!message.Headers.Contains(appSignature))
            {
                return false;
            }
            IEnumerator<string> enumeratorHeader = message.Headers.GetValues(appSignature).GetEnumerator();
            enumeratorHeader.MoveNext();
            string header = enumeratorHeader.Current;
            return (header == Key);
        }
    }
}