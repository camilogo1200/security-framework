using System;
using System.Configuration;
using System.Diagnostics;
using System.IO;
using System.Text;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Security.Framework.Cache;
using Security.Framework.Cryptography.Crypto;
using Security.Framework.Cryptography.Interfaces;
using Security.Framework.Exception;

namespace Security.Framework.Cryptography.Files
{
    public class FileUtilities : IFileUtilities
    {
        private string folderPath = String.Empty;
        private string certificateFileName = String.Empty;
        private string Fullpath = String.Empty;

        public PgpPublicKeyRing loadClientPublicCertificate(string tokenID)
        {
            PgpPublicKeyRing pgpPublicKeyRing = null;
            folderPath = ((TokenSession)UtilCache.MemoryInstance.GetItem(tokenID)).PublicKeyFilePath;
            //folderPath = ConfigurationManager.AppSettings["ClientCertificatesPath"];
            //certificateFileName = ConfigurationManager.AppSettings["clientPublicKeyFile"];
            Fullpath = folderPath;//Path.Combine(folderPath, certificateFileName);
            using (Stream inputStream = getStreamCertificateStr(Fullpath))
            {
                pgpPublicKeyRing = new PgpPublicKeyRing(inputStream);
            }
            return pgpPublicKeyRing;
        }

        private Stream getStreamCertificateStr(string keyPath)
        {
            Stream certificate = null;
            Stream keyIn = File.OpenRead(keyPath);
            certificate = PgpUtilities.GetDecoderStream(keyIn);
            return certificate;
        }

        public PgpPrivateKey loadPrivateKeyFromFile()
        {
            PgpPrivateKey pgpPrivKey = null;
            folderPath = ConfigurationManager.AppSettings["ServerCertificatesPath"];
            certificateFileName = ConfigurationManager.AppSettings["privateKeyFile"];
            // Fullpath = Path.Combine(folderPath, certificateFileName);
            // get pass private key
            string passPrivateKey = ConfigurationManager.AppSettings["passPrivateKey"];

            if (UtilCache.MemoryInstance.ExistItem(Properties.Messages.ParamCertPublicoServ))
            {
                Fullpath = (string)UtilCache.MemoryInstance.GetItem(Properties.Messages.ParamCertPrivServ);
            }

            if (UtilCache.MemoryInstance.ExistItem(Properties.Messages.ParamPassphraseCertPrivServ))
            {
                passPrivateKey = (string)UtilCache.MemoryInstance.GetItem(Properties.Messages.ParamPassphraseCertPrivServ);
            }

            char[] pass = passPrivateKey.ToCharArray();

            using (Stream inputStream = getStreamCertificateStr(Fullpath))
            {
                PgpSecretKeyRing pgpPriv = new PgpSecretKeyRing(inputStream);
                PgpSecretKey pgpPrivSecretKey = pgpPriv.GetSecretKey();
                pgpPrivKey = pgpPrivSecretKey.ExtractPrivateKeyUtf8(pass);
            }

            return pgpPrivKey;
        }

        public PgpPublicKeyRing loadPublicKeyFromFile()
        {
            PgpPublicKeyRing pgpPublicKeyRing = null;
            folderPath = ConfigurationManager.AppSettings["ServerCertificatesPath"];
            certificateFileName = ConfigurationManager.AppSettings["PublicKeyFile"];
            Fullpath = Path.Combine(folderPath, certificateFileName);

            using (Stream inputStream = getStreamCertificateStr(Fullpath))
            {
                pgpPublicKeyRing = new PgpPublicKeyRing(inputStream);
            }
            return pgpPublicKeyRing;
        }

        public bool SavePublicKeyFromClient(string cert, string path, string name)
        {
            try
            {
                byte[] inputStream = Encoding.UTF8.GetBytes(cert);
                //PgpPublicKeyRing pkr = new PgpPublicKeyRing(inputStream);
                using (var fs = new FileStream(path, FileMode.Create, FileAccess.Write))
                {
                    fs.Write(inputStream, 0, inputStream.Length);
                }
                //pkr.Encode(pubout);
                return CryptographyPGP.ImportPublicKey(path, name);
            }
            catch (System.Exception e)
            {
                AuditException.Instancia.WriteEntryOnLog(EventLogEntryType.Warning, string.Concat(Properties.Messages.GuardarCertificadoClienteError, e.Message), Properties.Messages.SourceName);
                throw new SecurityException(SecurityExceptionMessages.SEC_ErrorOnTokenRequest, string.Concat(Properties.Messages.GuardarCertificadoClienteError, e.Message));
            }
        }
    }
}