using System.Collections.Generic;

namespace Security.Framework.Communication.Interfaces
{
    public interface ISecureCommunicationHandling
    {
        /// <summary>
        /// Método encargado de resolver la URL final de envio al servidor
        /// apartir de la url template
        /// </summary>
        /// <returns>String final de envío al servidor, si no se encuentran los
        /// parametros necesarios para el reemplazo de la url template devuelve
        /// <code>MalformedUrlSecurityException</code>
        /// </returns>
        string getURL();

        /// <summary>
        /// Método encargado de realizar el envio del request al servidor
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        string sendMessage(SecureRequest request);

        IList<TEntity> sendMessage<TEntity>(SecureRequest request);

        //string sendFile(SecureRequest request,String path);
    }
}