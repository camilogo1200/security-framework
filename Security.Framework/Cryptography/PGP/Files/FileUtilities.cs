using Cache.Factory.Util;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;
using Security.Framework.Cryptography.Crypto;
using Security.Framework.Cryptography.Interfaces;
using Security.Framework.Exception;
using System;
using System.Configuration;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace Security.Framework.Cryptography.Files
{
    public class FileUtilities : IFileUtilities
    {
        private string folderPath = String.Empty;
        private string certificateFileName = String.Empty;
        private string Fullpath = String.Empty;
        private readonly IHashing hashing = new Hashing.Hashing();

        #region Generate PGP KeyPair

        public void GeneratePGPCertificates()
        {
            IAsymmetricCipherKeyPairGenerator kpg = GeneratorUtilities.GetKeyPairGenerator("RSA");
            bool armored = true;
            string fileExtension = null;
            fileExtension = (armored) ? ".asc" : ".gpg";

            string ServerKeyStrength = ConfigurationManager.AppSettings.Get("ServerKeyStrength");
            int keyStrength = 0;
            switch (ServerKeyStrength)
            {
                case "2048":
                    keyStrength = 2048;
                    break;

                case "3072":
                    keyStrength = 3096;
                    break;

                default:
                    keyStrength = 4096;
                    break;
            }
            kpg.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x10001), new SecureRandom(), keyStrength, 25));

            AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();
            string ServerPassphrase = hashing.GetSaltString(36);
            string PrivateKeyFilename = Guid.NewGuid().ToString() + Guid.NewGuid().ToString() + fileExtension;
            string PublicKeyFilename = Guid.NewGuid().ToString() + Guid.NewGuid().ToString() + fileExtension;

            ExportKeyPair(PrivateKeyFilename, PublicKeyFilename, kp.Public, kp.Private, "Interrapidisimo S.A.<soporte@interrapidisimo.com>", ServerPassphrase.ToCharArray(), armored);
        }

        #endregion Generate PGP KeyPair

        #region Export Keys

        private void ExportKeyPair(
        string privateKeyFileName,
        string publicKeyFileName,
        AsymmetricKeyParameter publicKey,
        AsymmetricKeyParameter privateKey,
        string identity,
        char[] passPhrase,
        bool armor)
        {
            string ServerCertificatesPath = ConfigurationManager.AppSettings.Get("ServerCertificatesPath");
            if (String.IsNullOrEmpty(ServerCertificatesPath))
            {
                throw new System.Exception("Ruta de certificados no encontrada en configuracion.");
            }
            string privateKeyPath = Path.Combine(ServerCertificatesPath, privateKeyFileName);
            string publicKeyPath = Path.Combine(ServerCertificatesPath, publicKeyFileName);
            Stream secretOut = null;
            Stream publicOut = null;
            try
            {
                secretOut = new FileStream(privateKeyPath, FileMode.Create, FileAccess.Write, FileShare.ReadWrite);
                publicOut = new FileStream(publicKeyPath, FileMode.Create, FileAccess.Write, FileShare.ReadWrite);

                if (armor)
                {
                    secretOut = new ArmoredOutputStream(secretOut);
                }

                PgpSecretKey secretKey = new PgpSecretKey(
                    PgpSignature.DefaultCertification,
                    PublicKeyAlgorithmTag.RsaGeneral,
                    publicKey,
                    privateKey,
                    DateTime.UtcNow,
                    identity,
                    SymmetricKeyAlgorithmTag.Cast5,
                    passPhrase,
                    null,
                    null,
                    new SecureRandom()
                    );

                secretKey.Encode(secretOut);

                if (armor)
                {
                    secretOut.Close();
                    publicOut = new ArmoredOutputStream(publicOut);
                }

                PgpPublicKey key = secretKey.PublicKey;

                key.Encode(publicOut);

                secretOut.Flush();
                publicOut.Flush();
            }
            finally
            {
                if (secretOut != null)
                {
                    secretOut.Dispose();
                    secretOut.Close();
                }
                if (publicOut != null)
                {
                    publicOut.Dispose();
                    publicOut.Close();
                }
            }
        }

        #endregion Export Keys

        public string readArmoredPGPKey(string fullPathKey)
        {
            if (String.IsNullOrEmpty(fullPathKey))
            {
                throw new ArgumentNullException(nameof(fullPathKey), "Archivo no valido.");
            }
            if (!File.Exists(fullPathKey))
            {
                throw new FileNotFoundException("Archivo no encontrado en la ruta", fullPathKey);
            }
            string pgpCertificate = File.ReadAllText(fullPathKey);
            return pgpCertificate;
        }

        public Stream GenerateStreamFromString(string s)
        {
            MemoryStream stream = new MemoryStream();
            StreamWriter writer = new StreamWriter(stream);
            writer.Write(s);
            writer.Flush();
            stream.Position = 0;
            return stream;
        }

        public void DecryptFile(
           string inputFileName,
           string keyFileName,
           char[] passwd,
           string defaultFileName)
        {
            using (Stream input = File.OpenRead(inputFileName),
                   keyIn = File.OpenRead(keyFileName))
            {
                DecryptFile(input, keyIn, passwd, defaultFileName);
            }
        }

        /**
		 * decrypt the passed in message stream
		 */

        private void DecryptFile(
            Stream inputStream,
            Stream keyIn,
            char[] passwd,
            string defaultFileName)
        {
            inputStream = PgpUtilities.GetDecoderStream(inputStream);

            try
            {
                PgpObjectFactory pgpF = new PgpObjectFactory(inputStream);
                PgpEncryptedDataList enc;

                PgpObject o = pgpF.NextPgpObject();
                //
                // the first object might be a PGP marker packet.
                //
                if (o is PgpEncryptedDataList)
                {
                    enc = (PgpEncryptedDataList)o;
                }
                else
                {
                    enc = (PgpEncryptedDataList)pgpF.NextPgpObject();
                }

                //
                // find the secret key
                //
                PgpPrivateKey sKey = null;
                PgpPublicKeyEncryptedData pbe = null;
                PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(
                    PgpUtilities.GetDecoderStream(keyIn));

                foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects())
                {
                    sKey = FindSecretKey(pgpSec, pked.KeyId, passwd);

                    if (sKey != null)
                    {
                        pbe = pked;
                        break;
                    }
                }

                if (sKey == null)
                {
                    throw new ArgumentException("secret key for message not found.");
                }

                Stream clear = pbe.GetDataStream(sKey);

                PgpObjectFactory plainFact = new PgpObjectFactory(clear);

                PgpObject message = plainFact.NextPgpObject();

                if (message is PgpCompressedData)
                {
                    PgpCompressedData cData = (PgpCompressedData)message;
                    PgpObjectFactory pgpFact = new PgpObjectFactory(cData.GetDataStream());

                    message = pgpFact.NextPgpObject();
                }

                if (message is PgpLiteralData)
                {
                    PgpLiteralData ld = (PgpLiteralData)message;

                    string outFileName = ld.FileName;
                    if (outFileName.Length == 0)
                    {
                        outFileName = defaultFileName;
                    }

                    Stream fOut = File.Create(outFileName);
                    Stream unc = ld.GetInputStream();
                    Streams.PipeAll(unc, fOut);
                    fOut.Close();
                }
                else if (message is PgpOnePassSignatureList)
                {
                    throw new PgpException("encrypted message contains a signed message - not literal data.");
                }
                else
                {
                    throw new PgpException("message is not a simple encrypted file - type unknown.");
                }

                if (pbe.IsIntegrityProtected())
                {
                    if (!pbe.Verify())
                    {
                        Console.Error.WriteLine("message failed integrity check");
                    }
                    else
                    {
                        Console.Error.WriteLine("message integrity check passed");
                    }
                }
                else
                {
                    Console.Error.WriteLine("no message integrity check");
                }
            }
            catch (PgpException e)
            {
                Console.Error.WriteLine(e);

                System.Exception underlyingException = e.InnerException;
                if (underlyingException != null)
                {
                    Console.Error.WriteLine(underlyingException.Message);
                    Console.Error.WriteLine(underlyingException.StackTrace);
                }
            }
        }

        /**
     * A simple routine that opens a key ring file and loads the first available key
     * suitable for encryption.
     *
     * @param input
     * @return
     * @throws IOException
     * @throws PGPException
     */

        public PgpPublicKey ReadPublicKey(Stream input)
        {
            PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(
                PgpUtilities.GetDecoderStream(input));

            //
            // we just loop through the collection till we find a key suitable for encryption, in the real
            // world you would probably want to be a bit smarter about this.
            //

            foreach (PgpPublicKeyRing keyRing in pgpPub.GetKeyRings())
            {
                foreach (PgpPublicKey key in keyRing.GetPublicKeys())
                {
                    if (key.IsEncryptionKey)
                    {
                        return key;
                    }
                }
            }

            throw new ArgumentException("Can't find encryption key in key ring.");
        }

        public PgpSecretKey ReadSecretKey(string fileName)
        {
            using (Stream keyIn = File.OpenRead(fileName))
            {
                return ReadSecretKey(keyIn);
            }
        }

        public PgpSecretKey ReadSecretKey(Stream input)
        {
            PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(
                PgpUtilities.GetDecoderStream(input));

            //
            // we just loop through the collection till we find a key suitable for encryption, in the real
            // world you would probably want to be a bit smarter about this.
            //

            foreach (PgpSecretKeyRing keyRing in pgpSec.GetKeyRings())
            {
                foreach (PgpSecretKey key in keyRing.GetSecretKeys())
                {
                    if (key.IsSigningKey)
                    {
                        return key;
                    }
                }
            }

            throw new ArgumentException("Can't find signing key in key ring.");
        }

        public byte[] CompressFile(string fileName, CompressionAlgorithmTag algorithm)
        {
            MemoryStream bOut = new MemoryStream();
            PgpCompressedDataGenerator comData = new PgpCompressedDataGenerator(algorithm);
            PgpUtilities.WriteFileToLiteralData(comData.Open(bOut), PgpLiteralData.Binary,
                new FileInfo(fileName));
            comData.Close();
            return bOut.ToArray();
        }

        /**
		 * Search a secret key ring collection for a secret key corresponding to keyID if it
		 * exists.
		 *
		 * @param pgpSec a secret key ring collection.
		 * @param keyID keyID we want.
		 * @param pass passphrase to decrypt secret key with.
		 * @return
		 * @throws PGPException
		 * @throws NoSuchProviderException
		 */

        public PgpPrivateKey FindSecretKey(PgpSecretKeyRingBundle pgpSec, long keyID, char[] pass)
        {
            PgpSecretKey pgpSecKey = pgpSec.GetSecretKey(keyID);

            if (pgpSecKey == null)
            {
                return null;
            }

            return pgpSecKey.ExtractPrivateKey(pass);
        }

        public PgpPublicKey ReadPublicKey(string fileName)
        {
            using (Stream keyIn = File.OpenRead(fileName))
            {
                return ReadPublicKey(keyIn);
            }
        }

        public bool IsFileInUse(string path)
        {
            FileInfo file = new FileInfo(path);
            FileStream stream = null;

            try
            {
                stream = file.Open(FileMode.Open, FileAccess.Read);
            }
            catch (System.Exception ex)
            {
                //the file is unavailable because it is:
                //still being written to
                //or being processed by another thread
                //or does not exist (has already been processed)
                return true;
            }
            finally
            {
                if (stream != null)
                    stream.Close();
            }

            //file is not locked
            return false;
        }

        #region Old utilities

        public PgpPublicKeyRing loadClientPublicCertificate(string tokenID)
        {
            PgpPublicKeyRing pgpPublicKeyRing = null;
            folderPath = ((TokenSession)UtilCache.MemoryInstance.GetItem(tokenID)).PublicKey;
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

        #endregion Old utilities
    }
}