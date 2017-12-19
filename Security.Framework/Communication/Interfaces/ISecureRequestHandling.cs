namespace Security.Framework.Communication.Interfaces
{
    /// <summary>
    /// Interface encargada de la definicion de comportamiento del
    /// objeto encargado de los request de manera segura al servidor.
    /// </summary>
    public interface ISecureRequestHandling
    {
        /// <summary>
        /// Método encargada de adicionar un encabezado al request
        /// </summary>
        /// <param name="key">Llave del encabezado <example><code>Content-Type</code></example></param>
        /// <param name="value">Valor del encabezado<example><code>application/json</code></example></param>
        void addHeader(string key, string value);

        /// <summary>
        /// Método encargada de adicionar un parametro para ser reemplazado en la url final
        /// </summary>
        /// <param name="key">Llave del parametro sin corchetes {id}<example><code>id</code></example></param>
        /// <param name="value">Valor del parametro<example><code>123456789</code></example></param>
        void addParameter(string key, string value);

        /// <summary>
        /// Método encargado de adicionar el contenido del cuerpo (Body) del request.
        /// </summary>
        /// <param name="JSONBody">Cuerpo del request</param>
        void addBody(string JSONBody);
    }
}