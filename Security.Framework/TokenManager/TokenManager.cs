using System;
using System.Security.Cryptography;
using System.Text;
using Security.Framework.Cache;
using Security.Framework.Cryptography.Crypto;

namespace Security.Framework.TokenManager
{
    public class TokenManager
    {
        private static readonly TokenManager instancia = new TokenManager();

        public static TokenManager Instancia
        {
            get { return TokenManager.instancia; }
        }

        public string GenerateTokenKey(string tokenBase, string username)
        {
            return string.Concat(tokenBase, ":", new CryptographyPGP().GenerateHash512(username), ":", GenerateKey(DateTime.Now, true));
        }

        public bool IsTokenValid(string tokenBaseId)
        {
            if (UtilCache.MemoryInstance.ExistItem(tokenBaseId))
            {
                try
                {
                    TokenSession ts = (TokenSession)UtilCache.MemoryInstance.GetItem(tokenBaseId);
                    return (ts.FechaExpiracion > DateTime.Now);
                }
                catch (System.Exception e)
                {
                    throw e;
                }
            }

            return false;
        }

        public bool IsTokenValid(string username, string tokenBaseId, out bool firstCheck)
        {
            firstCheck = false;
            try
            {
                if (UtilCache.MemoryInstance.ExistItem(string.Concat(tokenBaseId, ":", new CryptographyPGP().GenerateHash512(username), ":", GenerateKey(DateTime.Now, true))))
                {
                    TokenSession ts = (TokenSession)UtilCache.MemoryInstance.GetItem(string.Concat(tokenBaseId, ":", new CryptographyPGP().GenerateHash512(username), ":", GenerateKey(DateTime.Now, true)));
                    return (ts.FechaExpiracion > DateTime.Now);
                }

                if (UtilCache.MemoryInstance.ExistItem(tokenBaseId))
                {
                    firstCheck = true;
                    return firstCheck;
                }
            }
            catch
            {
                //security exception
            }
            return false;
        }

        public string GenerateKey(DateTime seed)
        {
            return GenerateKey(seed, false);
        }

        public string GenerateKey(DateTime seed, bool validateHour)
        {
            int day = seed.Day;
            int month = seed.Month;
            int week = (int)seed.DayOfWeek;
            int hour = seed.Hour;
            int keylength = day + month + week + (validateHour ? hour : 0);

            string resultString = string.Empty;
            keylength = keylength < 31 ? keylength + 31 : keylength;
            for (int i = keylength; i <= keylength * 2; i++)
            {
                resultString = string.Concat(resultString, ((char)i).ToString());
            }

            SHA256Managed hashstring = new SHA256Managed();
            byte[] hash = hashstring.ComputeHash(Encoding.UTF8.GetBytes(resultString));
            resultString = string.Empty;
            foreach (byte x in hash)
            {
                resultString += String.Format("{0:x2}", x);
            }

            return resultString;
        }
    }
}