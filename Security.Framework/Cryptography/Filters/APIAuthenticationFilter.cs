using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Resources;
using System.Web.Http;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;
using Newtonsoft.Json;
using Security.Framework.Cryptography.AES;
using Security.Framework.Cryptography.Crypto;
using Security.Framework.Exception;

namespace Security.Framework.Cryptography.Filters
{
    public class APIAuthenticationFilterAttribute : ActionFilterAttribute
    {
        private readonly CryptographyPGP cryptoPGP = new CryptographyPGP();

        public override void OnActionExecuting(HttpActionContext filterContext)
        {
            Type type = null;
            object paramValue = null;
            ResourceManager rm = new ResourceManager(typeof(Security.Framework.Properties.Messages));

            string rawRequest = null;
            string result = null;
            CryptoAES AES = new CryptoAES();
            IEnumerable<string> types;
            string fingerprint = string.Empty;

            if (filterContext.Request.Headers.TryGetValues("Fingerprint", out types))
            {
                fingerprint = types.FirstOrDefault();
            }

            try
            {
                // obtiene parametros de metodo Get y los descifra usando AES
                if (filterContext.Request.Method == HttpMethod.Get)
                {
                    foreach (var parameter in filterContext.ActionDescriptor.GetParameters())
                    {
                        paramValue = AES.EncryptDecrypt(filterContext.ActionArguments[parameter.ParameterName].ToString(), CryptographicProcess.Decrypt);
                        filterContext.ActionArguments[parameter.ParameterName] = paramValue;
                    }
                    return;
                }

                // obtiene los parametros que vienen en la url para descifrarlos con AES
                foreach (var parameter in filterContext.ActionDescriptor.GetParameters().Where(p => p.ParameterBinderAttribute != null))
                {
                    if (parameter.ParameterBinderAttribute.GetType() == typeof(FromUriAttribute))
                    {
                        paramValue = AES.EncryptDecrypt(filterContext.ActionArguments[parameter.ParameterName].ToString(), CryptographicProcess.Decrypt);
                        //paramValue = AES.EncryptDecrypt(paramValue.ToString(), CryptographicProcess.Decrypt);
                        filterContext.ActionArguments[parameter.ParameterName] = paramValue;
                    }
                }

                // obtiene el body del request y lo descifra
                using (var stream = new StreamReader(filterContext.Request.Content.ReadAsStreamAsync().Result))
                {
                    stream.BaseStream.Position = 0;
                    rawRequest = stream.ReadToEnd();
                }
                // resultado descifrado PGP
                result = CryptographyPGP.DecryptFile(rawRequest);

                if (String.IsNullOrEmpty(result))
                {
                    throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.BadRequest) { Content = new StringContent(rm.GetString("MensajeEntrada")) });
                }

                // compara que el hashing del header sea igual al del mensaje descifrado
                Hashing.Hashing hash = new Hashing.Hashing();
                IEnumerable<string> values;
                string authFingerprint = string.Empty;
                string poolNumber = string.Empty;
                if (filterContext.Request.Headers.TryGetValues("Fingerprint", out values))
                    authFingerprint = types.FirstOrDefault();

                authFingerprint = (string)JsonConvert.DeserializeObject(authFingerprint);
                if (!TokenManager.TokenManager.Instancia.IsTokenValid(authFingerprint))
                    throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.Unauthorized) { Content = new StringContent(rm.GetString("NoAutorizado: Error en la validación de token!!!!")) });

                //string nameParamHeaderHash = ConfigurationManager.AppSettings["NameAuthenticationHeader"];

                //string hashOrigin = hash.getHashingStr(result, Hashing.DigestAlgorithm.KECCAK_224);
                //if (!filterContext.Request.Headers.TryGetValues(nameParamHeaderHash, out values) || values.First() != hashOrigin)
                //{
                //    throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.BadRequest) { Content = new StringContent(rm.GetString("HasingEntrada")) });
                //}

                foreach (var parameter in filterContext.ActionDescriptor.GetParameters())
                {
                    // valida que el valor del parametro sea null y que no venga como parametro en la url(solo body)
                    if (filterContext.ActionArguments[parameter.ParameterName] == null && parameter.ParameterBinderAttribute?.GetType() != typeof(FromUriAttribute))
                    {
                        type = parameter.ParameterType;
                        paramValue = JsonConvert.DeserializeObject(result, type);
                        filterContext.ActionArguments[parameter.ParameterName] = paramValue;
                    }
                }
            }
            catch (System.Exception ex)
            {
                throw new HttpResponseException(new HttpResponseMessage(HttpStatusCode.Unauthorized) { Content = new StringContent(rm.GetString("NoAutorizado") + ex.Message) });
            }
        }

        public override void OnActionExecuted(HttpActionExecutedContext actionExecutedContext)
        {
            HttpResponseMessage response = actionExecutedContext.Response;
            if (response.StatusCode == HttpStatusCode.OK && response.Content != null)
            {
                ObjectContent contentObj = ((ObjectContent)response.Content);

                string contentStr = JsonConvert.SerializeObject(contentObj.Value, Formatting.Indented, new JsonSerializerSettings { ReferenceLoopHandling = ReferenceLoopHandling.Ignore });
                string fingerprint = string.Empty;
                HttpHeaders headers = response.Headers;
                IEnumerable<string> values;
                if (headers.TryGetValues("Fingerprint", out values))
                {
                    fingerprint = values.First();
                    contentObj.Value = CryptographyPGP.EncryptFile(contentStr, fingerprint);
                    return;
                }

                AuditException.Instancia.WriteEntryOnLog(System.Diagnostics.EventLogEntryType.Error, Properties.Messages.ErrorAuthTokenNoEncontrado, Properties.Messages.SourceName);
                throw new SecurityException(SecurityExceptionMessages.SEC_InvalidCredentials);
            }
        }
    }
}