using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Security.Framework.Cryptography.Files;
using Security.Framework.Cryptography.Interfaces;
using System;
using System.Security.Cryptography;
using System.Text;

namespace Security.Framework.Cryptography.AES
{
    public enum CryptographicProcess { Encrypt, Decrypt }

    /// <summary>
    /// AES encryption algorithm
    /// </summary>
    public class CryptoAES : IAESCipher
    {



        #region Singleton 
        /// <summary>         /// Atributo utilizado para evitar problemas con multithreading en el singleton.         /// </summary>         private readonly static object syncRoot = new Object();          private static volatile CryptoAES instance;

        public static CryptoAES Instance         {             get             {                 if (instance == null)                 {                     lock (syncRoot)                     {                         if (instance == null)                         {                             instance = new CryptoAES();                         }                     }                 }                 return instance;             }         }          //private CryptoAES()         //{          //}

        #endregion Singleton


        /// <summary>
        /// Encrypt or Decrypt message using AES. With public server key
        /// </summary>
        /// <param name="strToProcess"></param>
        /// <param name="isEncrypt"></param>
        /// <returns></returns>
        public string EncryptDecrypt(string strToProcess, CryptographicProcess process)
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

        public string EncryptDecrypt(string strToProcess, string passphrase, CryptographicProcess process)
        {
            bool isEncrypt = (process.ToString().Equals("Encrypt")) ? true : false;
            strToProcess = strToProcess.Trim();
            byte[] keyBytes = getKeyBytesAES(passphrase);
            KeyParameter key = ParameterUtilities.CreateKeyParameter("AES", keyBytes);
            IBufferedCipher cipher = CipherUtilities.GetCipher("AES/CBC/PKCS5PADDING");
            var iv = keyBytes;
            cipher.Init(isEncrypt, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("AES", keyBytes), iv));
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

        /// <summary>
        /// Encrypt or Decrypt message using AES. With public server key
        /// </summary>
        /// <param name="strToProcess"></param>
        /// <param name="isEncrypt"></param>
        /// <returns></returns>
        public string EncryptDecryptCBCPK7(string strToProcess,string pass , CryptographicProcess process)
        {
            strToProcess = strToProcess.Replace("\"", "");
            if (string.IsNullOrEmpty(strToProcess))
            {
                throw new System.Exception("Invalid AES Input Text");
            }
            bool isEncrypt = (process.Equals(CryptographicProcess.Encrypt)) ? true : false;

            strToProcess = strToProcess.Trim();

            // Debe traer llave de seguridad
            var keyBytes = Encoding.UTF8.GetBytes("7061737323313233");

            var iv = keyBytes;
            IBufferedCipher cipher = CipherUtilities.GetCipher("AES/CBC/PKCS7Padding");
            cipher.Init(isEncrypt, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("AES", keyBytes), iv));

            byte[] inputText = isEncrypt ? ASCIIEncoding.UTF8.GetBytes(strToProcess) : Convert.FromBase64String(strToProcess);
            if (inputText == null || inputText.Length == 0)
            {
                throw new System.Exception("Invalid Input Byte Array");
            }
            byte[] dec = cipher.DoFinal(inputText);

            string result = isEncrypt ? Convert.ToBase64String(dec) : Encoding.UTF8.GetString(dec);

            return result;
        }
    }
}