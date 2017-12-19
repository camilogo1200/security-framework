using System.Collections.Generic;

namespace Security.Framework.Exception
{
    public class MalformedUrlSecurityException : SecurityException
    {
        private string rawURL { get; set; }
        private string URL { get; set; }
        private IDictionary<string, string> Parameters { get; set; }

        //MalformedUrlSecurityException() : base() {
        //}
        public MalformedUrlSecurityException(string rawURL, string url, IDictionary<string, string> parameters = null)
        {
            this.URL = url;
            this.rawURL = rawURL;
            this.Parameters = parameters;
        }
    }
}