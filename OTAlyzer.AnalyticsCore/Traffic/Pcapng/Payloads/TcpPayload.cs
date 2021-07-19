using OTAlyzer.AnalyticsCore.Traffic.Pcapng.Packets;
using System.Text;

namespace OTAlyzer.AnalyticsCore.Traffic.Pcapng.Payloads
{
    public class TcpPayload : IPcapngPayload
    {
        public int Length => Payload.Length;

        public byte[] Payload { get; private set; }

        public TcpPacket TcpPacket { get; private set; }

        public static TcpPayload FromBytes(byte[] input, TcpPacket linkedTcpPacket = null)
        {
            return new TcpPayload() { Payload = input, TcpPacket = linkedTcpPacket };
        }

        public string GetString()
        {
            return Encoding.ASCII.GetString(Payload);
        }
    }
}