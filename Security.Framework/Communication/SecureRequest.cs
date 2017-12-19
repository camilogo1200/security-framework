using System;
using System.Collections.Generic;
using RestSharp;
using Security.Framework.Communication.Interfaces;
using Security.Framework.Cryptography.Crypto;
using Security.Framework.Cryptography.Hashing;

namespace Security.Framework.Communication
{
    /// <summary>
    /// Clase encargada del manejo de los request de manera segura
    /// </summary>
    public class SecureRequest : ISecureRequestHandling
    {
        private Hashing hash = new Hashing();
        private CryptographyPGP crypto = new CryptographyPGP();
        private string _encryptedBody = null;

        /// <summary>
        /// Parametros que se cifrarán y enviaran en la URL final al servidor
        /// </summary>
        public IDictionary<string, string> Parameters { get; set; }

        /// <summary>
        /// Headers que se cifrarán y enviaran en el request al servidor
        /// </summary>
        public IDictionary<string, string> Headers { get; set; }

        /// <summary>
        /// Enumerado que indica a que metodo utilizar en el envío del request
        /// </summary>
        public Method RequestMethod { get; set; }

        /// <summary>
        /// Cuerpo (Body) del request
        /// </summary>
        private string RawRequestBody { get; set; }

        /// <summary>
        /// Cuerpo (Body) del request
        /// </summary>
        //public string EncryptedBody
        //{
        //    get
        //    {
        //        if (_encryptedBody == null)
        //        {
        //            _encryptedBody = crypto.encrypt(RawRequestBody);
        //        }
        //        return _encryptedBody;
        //    }
        //}

        /// <summary>
        /// Firma de verificación de la información (Body)
        /// </summary>
        public string BodySignature { get { return getBodySignature(); } }

        /// <summary>
        /// Método encargada de adicionar un encabezado al request
        /// </summary>
        /// <param name="key">Llave del encabezado <example><code>Content-Type</code></example></param>
        /// <param name="value">Valor del encabezado<example><code>application/json</code></example></param>
        public void addHeader(string key, string value)
        {
            Headers.Add(key, value);
        }

        /// <summary>
        /// Método encargada de adicionar un parametro para ser reemplazado en la url final
        /// </summary>
        /// <param name="key">Llave del parametro sin corchetes {id}<example><code>id</code></example></param>
        /// <param name="value">Valor del parametro<example><code>123456789</code></example></param>
        public void addParameter(string key, string value)
        {
            Parameters.Add(key, value);
        }

        /// <summary>
        /// Método encargado de adicionar el contenido del cuerpo (Body) del request.
        /// </summary>
        /// <param name="JSONBody">Cuerpo del request</param>
        public void addBody(string JSONBody)
        {
            this.RawRequestBody = JSONBody;
        }

        /// <summary>
        /// Método encargado de creal la firma de verificación del contenido del request
        /// </summary>
        /// <returns></returns>
        private String getBodySignature()
        {
            string bodySignature;
            bodySignature = hash.getHashingStr(RawRequestBody, DigestAlgorithm.KECCAK_224);
            return bodySignature;
        }
    }
}