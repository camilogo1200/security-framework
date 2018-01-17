using System;
using System.Collections.Generic;
using System.Configuration;
using RestSharp;
using Security.Framework.Communication.Interfaces;
using Security.Framework.Cryptography.Crypto;
using Security.Framework.Exception;

namespace Security.Framework.Communication
{
    /// <summary>
    /// Clase encargada de manejar y controlar la comunicacion en el consumo de un servicio
    /// </summary>
    public class SecureCommunication : ISecureCommunicationHandling
    {
        private readonly CryptographyPGP crypto = new CryptographyPGP();

        /// <summary>
        /// URL template de envío al servidor sin HTTP:// o HTTPS://
        /// <example>(localhost/controlador/{id}/)</example>
        /// </summary>
        private string rawURL;

        public string HostURL
        {
            get { return getURL(); }
            set { rawURL = value; }
        }

        /// <summary>
        /// Resource URI <example><code>api/ingresos/{param}</code></example>
        /// </summary>
        public string resourceURI { get; set; }

        public SecureCommunication(string hostURL)
        {
            this.HostURL = hostURL;
        }

        public string sendMessage(SecureRequest request)
        {
            if (rawURL == null)
            {
                throw new InvalidHostURI(SecurityExceptionMessages.SEC_InvalidHostURI);
            }
            string rawData = null;
            var client = new RestClient(HostURL);

            RestRequest RSRequest = buildRestRequest(request);

            IRestResponse response = client.Execute(RSRequest);
            rawData = response.Content;

            string resultDecrypt = crypto.decrypt(rawData);
            return resultDecrypt;
        }

        private RestRequest buildRestRequest(SecureRequest request)
        {
            RestRequest rsRequest = new RestRequest(resourceURI, request.RequestMethod);

            //Add Parameters
            foreach (KeyValuePair<string, string> entry in request.Parameters)
            {
                rsRequest.AddUrlSegment(entry.Key, entry.Value);
            }

            //Add Headers
            foreach (KeyValuePair<string, string> entry in request.Headers)
            {
                rsRequest.AddHeader(entry.Key, entry.Value);
            }

            ////Query Strings
            //TODO Not supported for this version if query strings are available it takes care to add with AES as GET Method
            //rsRequest.AddParameter("name", "value"); // adds to POST or URL querystring based on Method

            String authenticationHeader = ConfigurationManager.AppSettings[""];

            rsRequest.AddHeader(authenticationHeader, request.BodySignature);

            return rsRequest;
        }

        public IList<TEntity> sendMessage<TEntity>(SecureRequest request)
        {
            IList<TEntity> lEntities = new List<TEntity>();
            string message = sendMessage(request);
            //TODO Parse message to Ilist of Entities

            throw new NotImplementedException();
            return lEntities;
        }

        /// <summary>
        /// Método que obtiene la URL final de envío al servidor (con datos reemplazados y cifrados)
        /// </summary>
        /// <returns></returns>
        public string getURL()
        {
            String finalURL = "";

            if (finalURL.Contains("{") || finalURL.Contains("}"))
            {
                throw new MalformedUrlSecurityException(rawURL, finalURL);
            }
            throw new NotImplementedException();
            return finalURL;
        }
    }
}