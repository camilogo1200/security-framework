using System.IO;

namespace Security.Framework.Cryptography.Interfaces
{
    public interface ICryptoPGP
    {
        string decrypt(string rawRequest);

        string encrypt(string strToEncrypt, string tokenID);

        string Decrypt(Stream inputStream);

        byte[] Encrypt(string rawResponse, string clientPGPCertificate);

        Stream replaceBreaks(Stream messageOrigen);

        string replaceBreakAndQuotationMarks(string rawRequest);
    }
}