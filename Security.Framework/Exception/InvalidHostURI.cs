namespace Security.Framework.Exception
{
    public class InvalidHostURI : SecurityException
    {
        public InvalidHostURI(SecurityExceptionMessages messageCode, string detalleError = null) : base(messageCode, detalleError)
        {
        }

        public InvalidHostURI(SecurityExceptionMessages messageCode) : base(messageCode)
        {
        }
    }
}