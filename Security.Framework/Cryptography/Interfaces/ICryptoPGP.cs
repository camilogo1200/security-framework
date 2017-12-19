namespace Security.Framework.Cryptography.Interfaces
{
    public interface ICryptoPGP
    {
        string decrypt(string rawRequest);

        string encrypt(string strToEncrypt, string tokenID);
    }
}