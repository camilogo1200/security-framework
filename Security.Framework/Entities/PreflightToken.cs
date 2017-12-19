namespace Security.Framework.Entities
{
    public class PreflightToken
    {
        public string MachineId { get; set; }
        public string Token { get; set; }
        public string PublicKeyFilePath { get; set; }
    }
}