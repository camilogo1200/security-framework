using System;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Security.Framework.Cryptography.Files;
using Security.Framework.Cryptography.Interfaces;

namespace Security.Framework.Cryptography.AES
{
    public enum CryptographicProcess { Encrypt, Decrypt }

    /// <summary>
    /// AES encryption algorithm
    /// </summary>
    public class CryptoAES : IAESCipher
    {
        /// <summary>
        /// Encrypt or Decrypt message using AES. With public server key
        /// </summary>
        /// <param name="strToProcess"></param>
        /// <param name="isEncrypt"></param>
        /// <returns></returns>
        public String EncryptDecrypt(String strToProcess, CryptographicProcess process)
        {
            bool isEncrypt = (process.ToString().Equals("Encrypt")) ? true : false;

            FileUtilities util = new FileUtilities();
            strToProcess = strToProcess.Trim();
            string keyText = Encoding.UTF8.GetString(util.loadPublicKeyFromFile().GetPublicKey().GetEncoded());
            byte[] keyBytes = getKeyBytesAES(keyText);
            KeyParameter key = ParameterUtilities.CreateKeyParameter("AES", keyBytes);
            IBufferedCipher cipher = CipherUtilities.GetCipher("AES/ECB/PKCS5PADDING");
            cipher.Init(isEncrypt, key);

            byte[] inputText = isEncrypt ? ASCIIEncoding.UTF8.GetBytes(strToProcess) : Convert.FromBase64String(strToProcess);

            byte[] dec = cipher.DoFinal(inputText);

            string result = isEncrypt ? Convert.ToBase64String(dec) : Encoding.UTF8.GetString(dec);

            return result;
        }
        public string EncryptDecrypt(String strToProcess, string passphrase, CryptographicProcess process)
        {
            bool isEncrypt = (process.ToString().Equals("Encrypt")) ? true : false;
            strToProcess = strToProcess.Trim();
            byte[] keyBytes = getKeyBytesAES(passphrase);
            KeyParameter key = ParameterUtilities.CreateKeyParameter("AES", keyBytes);
            IBufferedCipher cipher = CipherUtilities.GetCipher("AES/ECB/PKCS5PADDING");
            cipher.Init(isEncrypt, key);

            byte[] inputText = isEncrypt ? ASCIIEncoding.UTF8.GetBytes(strToProcess) : Convert.FromBase64String(strToProcess);

            byte[] dec = cipher.DoFinal(inputText);

            string result = isEncrypt ? Convert.ToBase64String(dec) : Encoding.UTF8.GetString(dec);

            return result;
        }




        /// <summary>
        /// Get key of the encryption
        /// </summary>
        /// <param name="keyPath"></param>
        /// <returns></returns>
        private static byte[] getKeyBytesAES(string keyText)
        {
            byte[] keyBytes = null;

            keyBytes = ASCIIEncoding.UTF8.GetBytes(keyText);
            var sha1 = SHA1Managed.Create();
            keyBytes = sha1.ComputeHash(keyBytes);
            keyBytes = Arrays.CopyOf(keyBytes, 32); // 256 bits
            return keyBytes;
        }
    }
}