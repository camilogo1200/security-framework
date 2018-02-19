using Security.Framework.Cryptography.AES;
using System;

namespace Security.Framework.Cryptography.Interfaces
{
    public interface IAESCipher
    {
        string EncryptDecrypt(string strToProcess, CryptographicProcess process);
        string EncryptDecrypt(string strToProcess, string passphrase, CryptographicProcess process);

        string EncryptDecryptCBCPK7(string strToProcess, string passphrase, CryptographicProcess process);
    }
}