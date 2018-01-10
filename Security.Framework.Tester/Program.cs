using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Security.Framework.Cryptography.AES;
using Security.Framework.Cryptography.Crypto;

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
            CryptographyPGP crypto = new CryptographyPGP();
            crypto.GeneratePGPCertificates();
            Console.WriteLine("Private Key : " + crypto.PrivateKeyFilename);
            Console.WriteLine("Public Key : " + crypto.PublicKeyFilename);
            Console.WriteLine("Passphrase Key : " + crypto.ServerPassphrase);
            Console.WriteLine("Public Key : " + crypto.PublicKey);
        }
    }
}
