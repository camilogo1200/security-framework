using Org.BouncyCastle.Bcpg.OpenPgp;
using Security.Framework.Cryptography.Files;
using System;
using System.Configuration;
using System.IO;

namespace Security.Framework.Tester
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            Program p = new Program();
            p.create();
            Console.ReadLine();
        }

        public void create()
        {
            FileUtilities fileUtils = new FileUtilities();
            string ServerCertificatesPath = ConfigurationManager.AppSettings.Get("ServerCertificatesPath");
            string publicKey = ConfigurationManager.AppSettings.Get("PublicKeyCertificate");
            string fullPath = Path.Combine(ServerCertificatesPath, publicKey);
            PgpPublicKey PublicKeyPGP = fileUtils.ReadPublicKey(fullPath);
        }
    }
}