using Cache.Factory.Util;
using Newtonsoft.Json;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;
using Security.Framework.Cryptography.Files;
using Security.Framework.Cryptography.Interfaces;
using Security.Framework.Exception;
using Security.Framework.Properties;
using System;
using System.Configuration;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

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

        private PgpSecretKey SecretKey { get; set; }

        private string _certificateClientRequest = null;

        private string folderPath = String.Empty;
        private string certificateFileName = String.Empty;
        private string Fullpath = String.Empty;
        private string passPrivateKey = String.Empty;
        private char[] pass = null;

        #region Singleton 
        /// <summary>         /// Atributo utilizado para evitar problemas con multithreading en el singleton.         /// </summary>         private readonly static object syncRoot = new Object();          private static volatile CryptographyPGP instance;

        public static CryptographyPGP Instance         {             get             {                 if (instance == null)                 {                     lock (syncRoot)                     {                         if (instance == null)                         {                             instance = new CryptographyPGP();                         }                     }                 }                 return instance;             }         }          private CryptographyPGP()         {          }

        #endregion Singleton

        /// <summary>
        /// Certificado del cliente
        /// </summary>
        public string CertificateClientRequest
        {
            get
            {
                if (_certificateClientRequest != null)
                {
                    _certificateClientRequest = replaceBreakAndQuotationMarks(_certificateClientRequest);
                }
                return _certificateClientRequest;
            }
            set // set method for storing value in name field.
            {
                _certificateClientRequest = value;
            }
        }

        /// <summary>
        /// Cifrar de C# a JS
        /// </summary>
        /// <param name="rawResponse"></param>
        /// <returns></returns>
        public byte[] Encrypt(string rawResponse, string clientPGPCertificate)
        {
            // convierte string en byte[]
            byte[] clearData = Encoding.ASCII.GetBytes(rawResponse);
            MemoryStream outputStream;
            // llave publica
            byte[] byteArrayCertificate = Encoding.UTF8.GetBytes(clientPGPCertificate);

            //if (String.IsNullOrEmpty(CertificateClientRequest))
            //{
            //    CertificateClientRequest = CertificateClientRequest;
            //}

            using (Stream publicKeyStream = new MemoryStream(byteArrayCertificate))
            {
                // obtiene la llave publica
                PgpPublicKey pubKey = ReadPublicKey(publicKeyStream);

                using (MemoryStream outputBytes = new MemoryStream())
                {
                    // comprime los datos entrantes
                    PgpCompressedDataGenerator dataCompressor = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);
                    Stream os = dataCompressor.Open(outputBytes);
                    PgpLiteralDataGenerator lData = new PgpLiteralDataGenerator();

                    Stream pOut = lData.Open(
                    os,
                    PgpLiteralData.Binary,
                    "DataPGP",
                    clearData.Length,
                    DateTime.UtcNow
                    );
                    pOut.Write(clearData, 0, clearData.Length);
                    pOut.Close();
                    dataCompressor.Close();

                    PgpEncryptedDataGenerator dataGenerator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5, false, new SecureRandom());
                    dataGenerator.AddMethod(pubKey);
                    // resultante de comprimir
                    byte[] dataBytes = outputBytes.ToArray();

                    using (outputStream = new MemoryStream())
                    {
                        // se arma el cuerpo del mensaje cifrado con encabezado
                        using (ArmoredOutputStream armoredStream = new ArmoredOutputStream(outputStream))
                        {
                            using (Stream outStream = dataGenerator.Open(armoredStream, dataBytes.Length))
                            {
                                outStream.Write(dataBytes, 0, dataBytes.Length);
                            }
                        }
                    }
                }
            }

            return outputStream.ToArray();
        }

        private static PgpPublicKey ReadPublicKey(Stream inputStream)
        {
            inputStream = PgpUtilities.GetDecoderStream(inputStream);
            PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(inputStream);

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

        /// <summary>
        /// Descifrar de JS a C#
        /// </summary>
        /// <param name="inputStream"></param>
        /// <returns></returns>

        public string Decrypt(Stream inputStream)
        {
            // certificados
            folderPath = ConfigurationManager.AppSettings["ServerCertificatesPath"];
            certificateFileName = ConfigurationManager.AppSettings["PrivateKeyFile"];
            passPrivateKey = ConfigurationManager.AppSettings["PassphrasePrivateKey"];
            Fullpath = Path.Combine(folderPath, certificateFileName);
            pass = passPrivateKey.ToCharArray();

            inputStream = PgpUtilities.GetDecoderStream(inputStream);

            string result = String.Empty;

            try
            {
                PgpObjectFactory pgpF = new PgpObjectFactory(inputStream);
                PgpEncryptedDataList enc;
                PgpObject o = pgpF.NextPgpObject();

                if (o is PgpEncryptedDataList)
                {
                    enc = (PgpEncryptedDataList)o;
                }
                else
                {
                    enc = (PgpEncryptedDataList)pgpF.NextPgpObject();
                }

                using (Stream inputStreamCertificate = File.Open(Fullpath, FileMode.Open))
                {
                    //////////////////////////////
                    PgpPrivateKey sKey = null;
                    PgpPublicKeyEncryptedData pbe = null;
                    PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(
                        PgpUtilities.GetDecoderStream(inputStreamCertificate));

                    foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects())
                    {
                        sKey = FindSecretKey(pgpSec, pked.KeyId, pass);

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

                    PgpObjectFactory plainFact = null;
                    using (Stream clear = pbe.GetDataStream(sKey))
                    {
                        plainFact = new PgpObjectFactory(clear);
                    }

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
                        Stream clearStream = ld.GetInputStream();
                        byte[] bytes = Streams.ReadAll(clearStream);
                        result = Encoding.UTF8.GetString(bytes);

                        clearStream.Close();
                    }
                    else if (message is PgpOnePassSignatureList)
                    {
                        throw new PgpException("encrypted message contains a signed message - not literal data.");
                    }
                    else
                    {
                        throw new PgpException("message is not a simple encrypted file - type unknown.");
                    }
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

            return result;
        }

        /// <summary>
        /// Encuentra la llave secreta
        /// </summary>
        /// <param name="pgpSec"></param>
        /// <param name="keyID"></param>
        /// <param name="pass"></param>
        /// <returns></returns>
        internal static PgpPrivateKey FindSecretKey(PgpSecretKeyRingBundle pgpSec, long keyID, char[] pass)
        {
            PgpSecretKey pgpSecKey = pgpSec.GetSecretKey(keyID);

            if (pgpSecKey == null)
            {
                return null;
            }

            return pgpSecKey.ExtractPrivateKey(pass);
        }

        /// <summary>
        /// Reemplaza comillas y saltos de linea
        /// </summary>
        /// <param name="rawRequest"></param>
        /// <returns></returns>
        public string replaceBreakAndQuotationMarks(string rawRequest)
        {
            string clearText = String.Empty;
            // Elimina espacios, reemplaza saltos de linea y comillas
            clearText = Regex.Replace(rawRequest, @"\\r\\n?|\\n", Environment.NewLine);
            clearText = clearText.Replace("\"", "");

            return clearText;
        }

        public string GenerateHash512(string value)
        {
            return hashing.getHashingStr(value, Hashing.DigestAlgorithm.SHA_512);
        }

        public void ReadPGPKeys()
        {
            string ServerCertificatesPath = ConfigurationManager.AppSettings.Get("ServerCertificatesPath");
            if (String.IsNullOrEmpty(ServerCertificatesPath))
            {
                throw new System.Exception("Ruta de certificados no encontrada en configuracion.");
            }
            string path = Path.Combine(ServerCertificatesPath, PrivateKeyFilename);

            if (!File.Exists(path))
            {
                throw new FileNotFoundException("Archivo no encontrado.", PrivateKeyFilename);
            }

            PrivateKey = File.ReadAllText(path);

            path = Path.Combine(ServerCertificatesPath, PublicKeyFilename);
            if (!File.Exists(path))
            {
                throw new FileNotFoundException("Archivo no encontrado.", PublicKeyFilename);
            }
            PublicKey = File.ReadAllText(path);
        }

        /// <summary>
        /// Elimina espacios, reemplaza saltos de linea y comillas en mensaje original
        /// </summary>
        /// <param name="messageOrigen"></param>
        /// <returns></returns>
        public Stream replaceBreaks(Stream messageOrigen)
        {
            string rawRequest = String.Empty;
            MemoryStream streamDescifrar = null;
            byte[] byteArray = null;
            // obtiene el body del request y lo descifra
            using (var stream = new StreamReader(messageOrigen))
            {
                stream.BaseStream.Position = 0;
                rawRequest = stream.ReadToEnd();
            }

            if (!String.IsNullOrEmpty(rawRequest))
            {
                // Elimina espacios, reemplaza saltos de linea y comillas
                rawRequest = replaceBreakAndQuotationMarks(rawRequest);

                // convertir string to stream
                byteArray = Encoding.UTF8.GetBytes(rawRequest);
                streamDescifrar = new MemoryStream(byteArray);
            }
            return streamDescifrar;
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

        #endregion Obsolete  GPG llamado a consola
    }
}