using System;

namespace Security.Framework
{
    public class TokenSession
    {
        public string UserId { get; set; }
        public string Token { get; set; }
        public string PublicKeyFilePath { get; set; }
        public string Username { get; set; }
        public int IdAplicacion { get; set; }
        public string MachineId { get; set; }
        public DateTime FechaCreacion { get; set; }
        public DateTime FechaExpiracion { get; set; }
    }
}