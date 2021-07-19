using OTAlyzer.AnalyticsCore.Analyzers.Objects.Enums;
using OTAlyzer.AnalyticsCore.Traffic.Pcapng.Packets;
using System.Text;

namespace OTAlyzer.AnalyticsCore.Traffic.Pcapng.Payloads
{
    public class MqttPayload : IPcapngPayload
    {
        public byte[] Payload { get; private set; }
        
        public string Content { get; private set; }
        
        public int Length { get; }

        public TcpPacket TcpPacket { get; private set; }

        public EncryptionType EncryptionType { get; private set; }

        public string Username { get; private set; }
        
        public string Password { get; private set; }
        
        public string Topic { get; private set; }
        
        public static MqttPayload FromText(string payloadString, TcpPacket linkedTcpPacket = null, string mqttHeaderFlags = null)
        {
            if (payloadString.Length == 0)
            {
                return null;
            }

            string content = payloadString;

            return new MqttPayload
            {
                Payload = Encoding.ASCII.GetBytes(payloadString),
                Content = content,
                TcpPacket = linkedTcpPacket, 
            };
        }
        
        public string GetString()
        {
            return Encoding.ASCII.GetString(Payload);
        }
    }
}