using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
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
            if (!message.Headers.Contains("x-app-signature"))
            {
                return false;
            }
            IEnumerator<string> enumeratorHeader = message.Headers.GetValues("x-app-signature").GetEnumerator();
            enumeratorHeader.MoveNext();
            string header = enumeratorHeader.Current;
            return (header == Key);
            return false;
        }
    }
}

