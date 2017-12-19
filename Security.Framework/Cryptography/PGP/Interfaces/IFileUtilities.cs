using Org.BouncyCastle.Bcpg.OpenPgp;

namespace Security.Framework.Cryptography.Interfaces
{
    public interface IFileUtilities
    {
        PgpPublicKeyRing loadPublicKeyFromFile();

        PgpPrivateKey loadPrivateKeyFromFile();

        PgpPublicKeyRing loadClientPublicCertificate(string tokenID);
    }
}