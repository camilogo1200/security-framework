using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Security.Framework.Cryptography.AES;
using Security.Framework.Cryptography.Crypto;
using Security.Framework.Cryptography.Files;

namespace Security.Framework.Tester
{
    class Program
    {
        static void Main(string[] args)
        {
            Program p = new Program();
            p.create();
            Console.ReadLine();
        }

       public void create() {
            FileUtilities fileUtils = new FileUtilities();
            string ServerCertificatesPath = ConfigurationManager.AppSettings.Get("ServerCertificatesPath");
            string publicKey = ConfigurationManager.AppSettings.Get("PublicKeyCertificate");
            string fullPath = Path.Combine(ServerCertificatesPath, publicKey);
            PgpPublicKey PublicKeyPGP = fileUtils.ReadPublicKey(fullPath);

            
 
        }
    }
}
