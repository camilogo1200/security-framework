using System;
using Security.Framework.Cryptography.AES;

namespace Security.Framework.Cryptography.Interfaces
{
    public interface IAESCipher
    {
        string EncryptDecrypt(String strToProcess, CryptographicProcess process);
    }
}