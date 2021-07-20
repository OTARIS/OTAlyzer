using OTAlyzer.AnalyticsCore.Traffic.Pcapng.Packets;
using OTAlyzer.AnalyticsCore.Traffic.Pcapng.Payloads;
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace OTAlyzer.AnalyticsCore.Traffic.Pcapng.Streams
{
    public class TcpStream
    {
        public TcpStream(byte[] ipAddressSource, byte[] ipAddressDestination, int originPort, int destinationPort)
        {
            Packets = new List<TcpPacket>();

            IpAddressSource = new IPAddress(ipAddressSource).ToString();
            IpAddressDestination = new IPAddress(ipAddressDestination).ToString();

            SourcePort = originPort;
            DestinationPort = destinationPort;
        }

        public byte[] Dataflow
        {
            get
            {
                List<byte> bytes = new List<byte>();

                foreach (TcpPacket tcpPacket in Packets)
                {
                    bytes.AddRange(tcpPacket.Payload);
                }

                return bytes.ToArray();
            }
        }

        public int DestinationPort { get; }

        public uint InitialAcknoweledgeNumberCtoS { get; set; }

        public uint InitialAcknoweledgeNumberStoC { get; set; }

        public uint InitialSequenceNumberCtoS { get; set; }

        public uint InitialSequenceNumberStoC { get; set; }

        public string IpAddressDestination { get; }

        public string IpAddressSource { get; }

        public List<TcpPacket> Packets { get; set; }

        public int SourcePort { get; }

        public List<TcpPacket> TlsPackets => Packets
            .Where(e => TlsPayload.IsTlsPayload(e.Payload))
            .ToList();
    }
}