using Cache.Factory;
using Cache.Factory.Interfaces;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;

namespace Security.Framework.MessageHandlers
{
    public class BodyEncryptionHandler : DelegatingHandler
    {
        private ICacheBehavior RuntimeCache = FactoryCacheHelper.Instance.RuntimeCache;

        protected async override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            HttpContent requestContent = request.Content;
            HttpRequestHeaders headers = request.Headers;

            if (requestContent != null)
            {
                DecryptContent(request);
            }
            var response = await base.SendAsync(request, cancellationToken);

            HttpContent responseContent = response.Content;
            if (responseContent != null)
            {
                EncryptContent(response);
            }
            return response;
        }

        private void EncryptContent(HttpResponseMessage response)
        {
            HttpContent ResponseContent = response.Content;
            string rawContent = ResponseContent.ReadAsStringAsync().Result;

            //Task<string> content = actionContext.Request.Content.ReadAsStringAsync();
        }

        private void DecryptContent(HttpRequestMessage request)
        {
            HttpMethod method = request.Method;
            if (method.Equals(HttpMethod.Post) || method.Equals(HttpMethod.Put) || method.Equals(HttpMethod.Delete))
            {
                string rawJson = request.Content.ReadAsStringAsync().Result;

                //if (RuntimeCache.ExistItem())
                //{
                //}
            }
        }
    }
}