using System;
using Security.Framework.Cryptography.AES;

namespace Security.Framework.Cryptography.Interfaces
{
    public interface IAESCipher
    {
        string EncryptDecrypt(String strToProcess, CryptographicProcess process);
        string EncryptDecrypt(String strToProcess, string passphrase, CryptographicProcess process);
    }
}