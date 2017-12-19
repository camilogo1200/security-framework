using System.Diagnostics;

namespace Security.Framework.Exception
{
    public class AuditException
    {
        private static readonly AuditException instancia = new AuditException();

        public static AuditException Instancia
        {
            get { return AuditException.instancia; }
        }

        public void WriteEntryOnLog(EventLogEntryType type, string message, string source)
        {
            EventLog.WriteEntry(source, message, type);
        }

        public void WriteEntryOnLog(string message, string source)
        {
            EventLog.WriteEntry(source, message);
        }

        public void WriteEntryOnLog(EventLogEntryType type, string message, string source, int eventID)
        {
            EventLog.WriteEntry(source, message, type, eventID);
        }

        public void WriteEntryOnLog(EventLogEntryType type, string message, string source, int eventID, short category)
        {
            EventLog.WriteEntry(source, message, type, eventID, category);
        }

        public void WriteEntryOnLog(EventLogEntryType type, string message, string source, int eventID, short category, byte[] rawData)
        {
            EventLog.WriteEntry(source, message, type, eventID, category, rawData);
        }
    }
}