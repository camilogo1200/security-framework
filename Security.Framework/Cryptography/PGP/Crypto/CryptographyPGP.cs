using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;
using Security.Framework.Cache;
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

        public string GenerateHash512(string value)
        {
            string resultString = string.Empty;
            using (SHA512 se = new SHA512Managed())
            {
                byte[] buffer = se.ComputeHash(Encoding.UTF8.GetBytes(value));
                resultString = BitConverter.ToString(buffer).Replace("-", "").ToLower();
            }

            return resultString;
        }

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
    }
}