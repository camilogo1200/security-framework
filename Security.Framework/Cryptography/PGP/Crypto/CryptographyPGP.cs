using System;
using System.Configuration;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Cache.Factory.Util;
using Newtonsoft.Json;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;
using Security.Framework.Cryptography.Files;
using Security.Framework.Cryptography.Interfaces;
using Security.Framework.Exception;
using Security.Framework.Properties;

namespace Security.Framework.Cryptography.Crypto
{
    /// <summary>
    /// RSA encryption algorithm
    /// </summary>
    /// </summary>
    public class CryptographyPGP : ICryptoPGP
    {

        private static readonly IHashing hashing = new Hashing.Hashing();
        public string PrivateKeyFilename { get; set; }
        public string PublicKeyFilename { get; set; }
        public string ServerPassphrase { get; set; }
        public AsymmetricCipherKeyPair KeyPair { get; set; }

        public string PublicKey { get; set; }
        public string PrivateKey { get; set; }


        PgpSecretKey SecretKey { get; set; }

        public CryptographyPGP()
        {
            // GeneratePGPCertificates();
        }


        /// <summary>
        /// Encrypt message (PGP)
        /// </summary>
        /// <param name="strToEncrypt"></param>
        /// <param name="publicKeyPath"></param>
        /// <returns></returns>
        public string encrypt(string strToEncrypt, string tokenID)
        {
            tokenID = JsonConvert.DeserializeObject<string>(tokenID);
            string crypto = null;
            FileUtilities util = new FileUtilities();
            PgpPublicKeyRing pgpPublicKeyRing = util.loadClientPublicCertificate(tokenID);
            AsymmetricKeyParameter publicKeyAsymetricParam = pgpPublicKeyRing.GetPublicKey().GetKey();

            MemoryStream cbOut = new MemoryStream();
            PgpEncryptedDataGenerator cPk = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, new SecureRandom());
            PgpPublicKey puK = pgpPublicKeyRing.GetPublicKey();

            cPk.AddMethod(puK);
            byte[] inBytes = Encoding.UTF8.GetBytes(strToEncrypt);
            Stream cOut = cPk.Open(cbOut, inBytes.Length);
            cOut.Write(inBytes, 0, inBytes.Length);
            cOut.Close();

            byte[] outBytes = cbOut.ToArray();
            crypto = Convert.ToBase64String(outBytes);
            return crypto;
        }

        /// <summary>
        /// Decypt message (PGP)
        /// </summary>
        /// <param name="rawRequest">Content request</param>
        /// <returns></returns>
        public string decrypt(string rawRequest)
        {
            //rawRequest = rawRequest.Replace("\n", "");
            //rawRequest = rawRequest.Replace("\r", "");
            string result = String.Empty;
            FileUtilities util = new FileUtilities();
            byte[] encryptedBytes = Convert.FromBase64String(rawRequest);
            PgpObjectFactory pgpF = new PgpObjectFactory(encryptedBytes);
            PgpEncryptedDataList encList = null;
            PgpObject obj = pgpF.NextPgpObject();
            if (obj is PgpEncryptedDataList)
            {
                encList = (PgpEncryptedDataList)obj;
            }
            else
            {
                encList = (PgpEncryptedDataList)pgpF.NextPgpObject();
            }

            PgpPublicKeyEncryptedData encP = (PgpPublicKeyEncryptedData)encList[0];
            PgpPrivateKey pgpPrivKey = util.loadPrivateKeyFromFile();

            using (Stream clear = encP.GetDataStream(pgpPrivKey))
            {
                byte[] bytes = Streams.ReadAll(clear);
                result = Encoding.UTF8.GetString(bytes);
            }

            return result;
        }

        public string Decrypt(string base64Input, string privatePath)
        {
            FileUtilities util = new FileUtilities();
            privatePath = privatePath == string.Empty ? ((string)UtilCache.MemoryInstance.GetItem("RutaCertificadosServidorPrivado")) : privatePath;

            Lazy<IAsymmetricBlockCipher> _cipher = new Lazy<IAsymmetricBlockCipher>(() =>
           {
               var rsa = new Pkcs1Encoding(new RsaEngine());
               var pemReader = new PemReader(new StringReader(privatePath));
               var keyPair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
               rsa.Init(false, keyPair.Private);
               return rsa;
           });

            var buf = Convert.FromBase64String(base64Input);
            byte[] block = _cipher.Value.ProcessBlock(buf, 0, buf.Length);

            return Encoding.UTF8.GetString(block);
        }

        public string GenerateHash512(string value)
        {
            return hashing.getHashingStr(value, Hashing.DigestAlgorithm.SHA_512);
        }

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
            KeyPair = kp;
            ServerPassphrase = hashing.GetSaltString(36);
            PrivateKeyFilename = Guid.NewGuid().ToString() + Guid.NewGuid().ToString() + fileExtension;
            PublicKeyFilename = Guid.NewGuid().ToString() + Guid.NewGuid().ToString() + fileExtension;
        
            ExportKeyPair(PrivateKeyFilename, PublicKeyFilename, kp.Public, kp.Private, "Interrapidisimo S.A.<soporte@interrapidisimo.com>", ServerPassphrase.ToCharArray(), armored);
            
            ReadPGPKeys();
        }

        private void ReadPGPKeys()
        {
            string ServerCertificatesPath = ConfigurationManager.AppSettings.Get("ServerCertificatesPath");
            if (String.IsNullOrEmpty(ServerCertificatesPath))
            {
                throw new System.Exception("Ruta de certificados no encontrada en configuracion.");
            }
            string path = Path.Combine(ServerCertificatesPath,PrivateKeyFilename);

            if (!File.Exists(path)){
                throw new FileNotFoundException("Archivo no encontrado.", PrivateKeyFilename);
            }
            while (IsFileInUse(path)) {
               // Console.WriteLine("Sleep... ");
                //Thread.Sleep(2000);
            }
            PrivateKey = File.ReadAllText(path);

             path = Path.Combine(ServerCertificatesPath, PublicKeyFilename);
            if (!File.Exists(path)){
                throw new FileNotFoundException("Archivo no encontrado.", PublicKeyFilename);
            }
            PublicKey = File.ReadAllText(path);
            
        }

        private bool IsFileInUse(string path)
        {
            FileInfo file = new FileInfo(path);
            FileStream stream = null;

            try
            {
                stream = file.Open(FileMode.Open, FileAccess.Read);
            }
            catch (IOException)
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
                secretOut = new FileStream(privateKeyPath, FileMode.Create, FileAccess.Write, FileShare.Read);
                publicOut = new FileStream(publicKeyPath, FileMode.Create, FileAccess.Write, FileShare.Read);

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


        #region Obsolete  GPG llamado a consola 

        [Obsolete("Utiliza llamado a consola, no escalable")]
        public static string EncryptFile(string rawEncrypted, string fingerprint)
        {
            fingerprint = JsonConvert.DeserializeObject<string>(fingerprint);
            if (!UtilCache.MemoryInstance.ExistItem(fingerprint) || !UtilCache.MemoryInstance.ExistItem(Messages.ParamRutaMensajeDecriptado))
                throw new SecurityException(SecurityExceptionMessages.SEC_InvalidCredentials, "No se encontraron rutas de archivos de encripcion persistentes.", null);

            TokenSession currentClient = (TokenSession)UtilCache.MemoryInstance.GetItem(fingerprint);
            string rutaMensajes = Path.GetDirectoryName((string)UtilCache.MemoryInstance.GetItem(Messages.ParamRutaMensajeDecriptado));

            string rutaMensajeEncryptado = string.Concat(rutaMensajes, "\\", currentClient.MachineId, "Encrypted.asc");
            string rutaMensajeDecryptado = string.Concat(rutaMensajes, "\\", currentClient.MachineId, "Decrypted.asc");

            System.IO.File.WriteAllLines(rutaMensajeEncryptado, rawEncrypted.Split('\n'));

            FileInfo info = new FileInfo(rutaMensajeEncryptado);
            //string decryptedFileName = info.FullName.Substring(0, info.FullName.LastIndexOf('.')) + "Dec.TXT";
            //string encryptedFileName = info.FullName;
            System.Diagnostics.ProcessStartInfo psi = new System.Diagnostics.ProcessStartInfo("cmd.exe");
            psi.CreateNoWindow = false;
            psi.UseShellExecute = false;
            psi.RedirectStandardInput = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            psi.WorkingDirectory = @System.Configuration.ConfigurationManager.AppSettings["GPGDirectory"].ToString();
            System.Diagnostics.Process process = System.Diagnostics.Process.Start(psi);
            //string sCommandLine = "echo " + passPhraseCertPrivServ + "|gpg.exe --passphrase-fd 0 --batch --verbose --yes --output " + rutaMensajeDecryptado + @" --decrypt " + rutaMensajeEncryptado;
            string sCommandLine = "gpg --batch --armor --trust-model always -e -r " + currentClient.MachineId + " " + rutaMensajeEncryptado;
            process.StandardInput.WriteLine(sCommandLine);
            process.StandardInput.Flush();
            process.StandardInput.Close();
            process.WaitForExit();
            //System.Diagnostics.Process.Start("CMD.exe", sCommandLine);
            string result = process.StandardOutput.ReadToEnd();
            string error = process.StandardError.ReadToEnd();
            process.Close();
            string resultLines = string.Join("\n", File.ReadAllLines(string.Concat(rutaMensajeEncryptado, ".asc")));
            File.Delete(string.Concat(rutaMensajeEncryptado, ".asc"));
            return resultLines;
        }

        [Obsolete("No debe ser utilizado, este metodo utiliza el llamado a consola de gpg")]
        public static bool ImportPublicKey(string rutaPubCert, string clientId)
        {
            FileInfo info = new FileInfo(rutaPubCert);
            System.Diagnostics.ProcessStartInfo psi = new System.Diagnostics.ProcessStartInfo("cmd.exe");
            psi.CreateNoWindow = false;
            psi.UseShellExecute = false;
            psi.RedirectStandardInput = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            psi.WorkingDirectory = @System.Configuration.ConfigurationManager.AppSettings["GPGDirectory"].ToString();
            System.Diagnostics.Process process = System.Diagnostics.Process.Start(psi);
            //string sCommandLine = "echo " + passPhraseCertPrivServ + "|gpg.exe --passphrase-fd 0 --batch --verbose --yes --output " + rutaMensajeDecryptado + @" --decrypt " + rutaMensajeEncryptado;
            string sCommandLine = string.Concat("gpg --import ", rutaPubCert);
            process.StandardInput.WriteLine(sCommandLine);
            process.StandardInput.Flush();
            process.StandardInput.Close();
            process.WaitForExit();

            string result = process.StandardOutput.ReadToEnd();
            string error = process.StandardError.ReadToEnd();
            process.Close();
            return true;
        }

        [Obsolete("Utiliza llamado a consola, no escalable")]
        public static string DecryptFile(string rawEncrypted)
        {
            if (!UtilCache.MemoryInstance.ExistItem(Messages.ParamRutaMensajeDecriptado) || !UtilCache.MemoryInstance.ExistItem(Messages.ParamRutaMensajeEncriptado))
                throw new SecurityException(SecurityExceptionMessages.SEC_InvalidCredentials, "No se encontraron rutas de archivos de encripcion persistentes.", null);

            string rutaMensajeEncryptado = (string)UtilCache.MemoryInstance.GetItem(Messages.ParamRutaMensajeEncriptado);
            string rutaMensajeDecryptado = (string)UtilCache.MemoryInstance.GetItem(Messages.ParamRutaMensajeDecriptado);

            if (!File.Exists(rutaMensajeEncryptado))//|| !File.Exists(rutaMensajeDecryptado))
                throw new SecurityException(SecurityExceptionMessages.SEC_InvalidCredentials, "No se encontraron archivos de encripcion.", null);

            if (!UtilCache.MemoryInstance.ExistItem(Messages.ParamPassphraseCertPrivServ))
                throw new SecurityException(SecurityExceptionMessages.SEC_InvalidCredentials, "No se pudo obtener credencial de certificado privado.", null);

            string passPhraseCertPrivServ = (string)UtilCache.MemoryInstance.GetItem(Messages.ParamPassphraseCertPrivServ);
            string rutaPrivadoServidor = (string)UtilCache.MemoryInstance.GetItem(Messages.ParamCertPrivServ);

            System.IO.File.WriteAllLines(rutaMensajeEncryptado, rawEncrypted.Split('\n'));

            FileInfo info = new FileInfo(rutaMensajeEncryptado);
            //string decryptedFileName = info.FullName.Substring(0, info.FullName.LastIndexOf('.')) + "Dec.TXT";
            //string encryptedFileName = info.FullName;
            System.Diagnostics.ProcessStartInfo psi = new System.Diagnostics.ProcessStartInfo("cmd.exe");
            psi.CreateNoWindow = false;
            psi.UseShellExecute = false;
            psi.RedirectStandardInput = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            psi.WorkingDirectory = @System.Configuration.ConfigurationManager.AppSettings["GPGDirectory"].ToString();
            System.Diagnostics.Process process = System.Diagnostics.Process.Start(psi);
            //string sCommandLine = "echo " + passPhraseCertPrivServ + "|gpg.exe --passphrase-fd 0 --batch --verbose --yes --output " + rutaMensajeDecryptado + @" --decrypt " + rutaMensajeEncryptado;
            string sCommandLine = "echo " + passPhraseCertPrivServ + "| gpg --batch --passphrase-fd 0 -o \"" + rutaMensajeDecryptado + "\" --decrypt \"" + rutaMensajeEncryptado + "\"";
            process.StandardInput.WriteLine(sCommandLine);
            process.StandardInput.Flush();
            process.StandardInput.Close();
            process.WaitForExit();
            //System.Diagnostics.Process.Start("CMD.exe", sCommandLine);
            string result = process.StandardOutput.ReadToEnd();
            string error = process.StandardError.ReadToEnd();
            process.Close();
            string resultLines = string.Join(string.Empty, File.ReadAllLines(rutaMensajeDecryptado));
            File.Delete(rutaMensajeDecryptado);
            return resultLines;
        }


        #endregion

    }
}