using Cache.Factory;
using Cache.Factory.Interfaces;
using Newtonsoft.Json.Linq;
using Security.Framework.Cryptography.AES;
using Security.Framework.Cryptography.Crypto;
using Security.Framework.Cryptography.Interfaces;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;

namespace Security.Framework.MessageHandlers
{
    public class RequestBodyHandler : DelegatingHandler
    {
        private readonly ICryptoPGP cryptography = CryptographyPGP.Instance;
        private readonly ICacheBehavior RuntimeCache = FactoryCacheHelper.Instance.RuntimeCache;
        private string idTokenCliente;

        protected async override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (!request.Method.Equals(HttpMethod.Options))
            {
                HttpContent content = request.Content;
                if (request.RequestUri.AbsolutePath.Contains("auth") && !request.Method.Equals(HttpMethod.Get))
                {
                    IList<string> lHeaders = request.Headers.GetValues("machine-signature").ToList();
                    if (lHeaders == null || lHeaders.Count < 1)
                    {
                        System.IO.File.WriteAllText(@"C:\Seguridad\ErrorSeguridad.txt", "Machine signature not found", Encoding.UTF8);
                        throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.BadRequest)
                        {
                            Content = new StringContent("Machine signature not found")
                        });
                    }
                    this.idTokenCliente = lHeaders[0];
                    if (RuntimeCache.ExistItem(this.idTokenCliente))
                    {
                        RuntimeCache.DeleteItem(this.idTokenCliente);
                    }
                }

                //TODO Header cache token y pgp sino llamar a seguridad
                if (content != null && !request.Method.Equals(HttpMethod.Get))
                {
                    DecryptPGPContent(request);
                }
                else
                {
                    EncryptParamAES(request);
                }
            }
            var response = await base.SendAsync(request, cancellationToken);
            if (!request.Method.Equals(HttpMethod.Options))
            {
                if (response.Content != null)
                {
                    if (!request.Method.Equals(HttpMethod.Get))
                    {
                        EncryptPGPContent(response, RuntimeCache.GetItem(idTokenCliente).ToString());
                    }
                }
            }
            return response;
        }

        private void EncryptParamAES(HttpRequestMessage request)
        {
            IAESCipher AES = new CryptoAES();
            var baseUri = request.RequestUri.GetComponents(UriComponents.Scheme | UriComponents.Host | UriComponents.Port | UriComponents.Path, UriFormat.UriEscaped);
            var qs = HttpUtility.ParseQueryString(request.RequestUri.Query);

            if (request.GetQueryNameValuePairs().Any())
            {
                string passphrase = "";//TODO PASSPHRASE
                foreach (var parameter in request.GetQueryNameValuePairs())
                {
                    //qs.Set(parameter.Key, AES.EncryptDecryptCBCPK7(parameter.Value, passphrase, CryptographicProcess.Decrypt));
                }
                request.RequestUri = new Uri(string.Format("{0}?{1}", baseUri, qs.ToString()));
            }
        }

        private void EncryptPGPContent(HttpResponseMessage response, string clientPGPCertificate)
        {
            HttpContent ResponseContent = response.Content;
            string rawContent = ResponseContent.ReadAsStringAsync().Result;
            byte[] byteArray = cryptography.Encrypt(rawContent, clientPGPCertificate);

            string result = Encoding.UTF8.GetString(byteArray);
            if (String.IsNullOrEmpty(result))
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.BadRequest)
                {
                    Content = new StringContent("Error al cifrar respuesta!")
                });
            }

            response.Content = new StringContent(result, Encoding.UTF8, "text/plain");
        }

        private void DecryptPGPContent(HttpRequestMessage request)
        {
            try
            {
                Stream rawRequest = null;
                string result = null;
                string mediaType = request.Content.Headers.ContentType.MediaType;
                // Elimina saltos de linea y comillas
                rawRequest = cryptography.replaceBreaks(request.Content.ReadAsStreamAsync().Result);
                if (rawRequest == null)
                {
                    throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.BadRequest)
                    {
                        Content = new StringContent("Mensaje de entrada no valido")
                    });
                }

                // resultado descifrado PGP
                result = cryptography.Decrypt(rawRequest);
                if (String.IsNullOrEmpty(result))
                {
                    System.IO.File.WriteAllText(@"C:\Seguridad\ErrorSeguridad.txt", "Mensaje (result) no valido", Encoding.UTF8);
                    throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.BadRequest)
                    {
                        Content = new StringContent("Mensaje de entrada no valido")
                    });
                }

                // Serializa request para obtener el certificado publico del cliente
                JObject jObject = JObject.Parse(result);
                if (request.RequestUri.AbsolutePath.Contains("auth") &&
                    !request.Method.Equals(HttpMethod.Get) &&
                !RuntimeCache.ExistItem(idTokenCliente))
                {
                    string clientPublicKey = (string)jObject.SelectToken("Machine.PgpPublicKey");
                    if (String.IsNullOrEmpty(clientPublicKey))
                    {
                        System.IO.File.WriteAllText(@"C:\Seguridad\ErrorSeguridad.txt", "Certificado publico cliente no valido", Encoding.UTF8);
                        throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.BadRequest)
                        {
                            Content = new StringContent("Certificado publico cliente no valido")
                        });
                    }
                    RuntimeCache.AddItem(idTokenCliente, clientPublicKey);
                }
                //TODO cache Machine.PgpPublicKey

                // transforma el contenido al formato media type entrante
                var content = new StringContent(result, Encoding.UTF8, mediaType);

                request.Content = content;
            }
            catch (System.Exception Ex)
            {
                String exst = Ex.Message + Environment.NewLine + Ex.StackTrace;
                System.IO.File.WriteAllText(@"C:\Seguridad\ErrorSeguridad.txt", " [ Catch NULL ] " + exst,Encoding.UTF8);
            }
        }

        /// <summary>
        /// Elimina espacios, reemplaza saltos de linea y comillas en mensaje original
        /// </summary>
        /// <param name="messageOrigen"></param>
        /// <returns></returns>
        public Stream replaceBreaks(Stream messageOrigen)
        {
            string rawRequest = String.Empty;
            MemoryStream streamDescifrar = null;
            byte[] byteArray = null;
            // obtiene el body del request y lo descifra
            using (var stream = new StreamReader(messageOrigen))
            {
                stream.BaseStream.Position = 0;
                rawRequest = stream.ReadToEnd();
            }

            if (!String.IsNullOrEmpty(rawRequest))
            {
                // Elimina espacios, reemplaza saltos de linea y comillas
                rawRequest = cryptography.replaceBreakAndQuotationMarks(rawRequest);

                // convertir string to stream
                byteArray = Encoding.UTF8.GetBytes(rawRequest);
                streamDescifrar = new MemoryStream(byteArray);
            }
            return streamDescifrar;
        }
    }
}