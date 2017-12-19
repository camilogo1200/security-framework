using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;

namespace Security.Framework.Exception
{
    public enum SecurityExceptionMessages { SEC_InvalidHostURI, SEC_InvalidCredentials, SEC_ErrorOnTokenRequest }

    [Serializable()]
    public class SecurityException : System.Exception
    {
        public SecurityException() : base()
        {
        }

        public SecurityException(SecurityExceptionMessages messageCode, String DetalleError, Dictionary<String, String> Parametros = null)
        {
            this.GuidExcepcion = new Guid();
            this.Fecha_Excepcion = DateTime.Now;
            this.CodigoError = messageCode.ToString();
            this.MensajeError = DetalleError;
            this.Parametros = Parametros;
        }

        public SecurityException(SecurityExceptionMessages messageCode, Dictionary<String, String> Parametros = null)
        {
            this.GuidExcepcion = new Guid();
            this.Fecha_Excepcion = DateTime.Now;
            //TODO is this a generic error handler?
            //FIXME
            CodigoError = messageCode.ToString();
            this.Parametros = Parametros;
        }

        /// <summary>
        /// Id de la excepcion
        /// </summary>
        [Column("EXC_GuidExcepcion")]
        public Guid GuidExcepcion { get; set; }

        /// <summary>
        /// Codigo de error
        /// </summary>
        [Column("EXC_CodigoError")]
        public String CodigoError { get; set; }

        /// <summary>
        /// Mensaje de error
        /// </summary>
        [Column("EXC_MensajeError")]
        public String MensajeError { get; set; }

        /// <summary>
        /// Ubicacion de error: Nombre de espacios y metodo
        /// </summary>
        [Column("EXC_Ubicacion")]
        public String Ubicacion { get; set; }

        /// <summary>
        /// Parametros de entrada
        /// </summary>
        [Column("EXC_Parametros")]
        public Dictionary<String, String> Parametros { get; set; }

        /// <summary>
        /// Fecha excepcion
        /// </summary>
        [Column("EXC_Fecha_Excepcion")]
        public DateTime Fecha_Excepcion { get; set; }
    }
}