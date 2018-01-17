using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Security.Framework.Cryptography.Hashing;
using Security.Framework.Cryptography.Interfaces;

namespace Security.Framework.MessageHandlers
{
    public class ResponseHeadersHandler : DelegatingHandler
    {
        private readonly IHashing hashing = new Hashing();
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var response = await base.SendAsync(request, cancellationToken);
            AddBodySignatureHeaders(response);
            return response;
        }

        private void AddBodySignatureHeaders(HttpResponseMessage response)
        {
            HttpContent requestContent = response.Content;
            string jsonContent = requestContent.ReadAsStringAsync().Result;
            string SHA3 = hashing.getHashingStr(jsonContent, DigestAlgorithm.SHA3_256);
            response.Headers.Add("X-body-signature", SHA3);
        }
    }
}
