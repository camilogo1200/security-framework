using System;

namespace Security.Framework.Entities
{
    public class PGPCertificate

    {
        public byte[] RawCertificate { get; set; }
        public byte[] RawFingerprint { get; set; }
        public byte[] RawPassphrase { get; set; }

        public String getCertificate()
        {
            return System.Text.Encoding.UTF8.GetString(RawCertificate);
        }

        public String getFingerprint()
        {
            return System.Text.Encoding.UTF8.GetString(RawFingerprint);
        }

        public String getPassPhrase()
        {
            return System.Text.Encoding.UTF8.GetString(RawPassphrase);
        }
    }
}