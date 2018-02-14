using Security.Framework.Cryptography.Hashing;
using Security.Framework.Cryptography.Interfaces;
using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

namespace Security.Framework.MessageHandlers
{
    public class ResponseHeadersHandler : DelegatingHandler
    {
        private readonly IHashing hashing = new Hashing();

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var response = await base.SendAsync(request, cancellationToken);
            AddBodySignatureHeaders(response);
            setCacheExpirationTime(response);
            return response;
        }

        private void setCacheExpirationTime(HttpResponseMessage response)
        {
            if (response.Headers.CacheControl != null)
            {
                response.Headers.CacheControl.NoStore = true;
                response.Headers.CacheControl.NoCache = true;
            }

            HttpContext.Current.Response.Cache.SetCacheability(HttpCacheability.Public);
            HttpContext.Current.Response.Cache.SetExpires(DateTime.Now.AddMinutes(15));
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