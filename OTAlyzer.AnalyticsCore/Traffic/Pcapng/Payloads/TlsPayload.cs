using OTAlyzer.AnalyticsCore.Traffic.Pcapng.Packets;
using OTAlyzer.AnalyticsCore.Traffic.Pcapng.Payloads.Enums;
using System;
using System.IO;
using System.Linq;
using System.Text;

namespace OTAlyzer.AnalyticsCore.Traffic.Pcapng.Payloads
{
    public class TlsPayload : IPcapngPayload
    {
        public byte[] AdditionalPayload { get; private set; }

        public TlsContentType ContentType { get; private set; }

        public int Length => Payload.Length;

        public byte[] Payload { get; private set; }

        public ushort PayloadLenght { get; private set; }

        public TcpPacket TcpPacket { get; private set; }

        public TlsVersion Version { get; private set; }

        public static TlsPayload FromBytes(byte[] input, TcpPacket linkedTcpPacket = null)
        {
            if (input.Length == 0)
            {
                return null;
            }

            TlsPayload tlsPayload = new TlsPayload
            {
                TcpPacket = linkedTcpPacket
            };

            using (MemoryStream memoryStream = new MemoryStream(input))
            using (BinaryReader reader = new BinaryReader(memoryStream))
            {
                tlsPayload.ContentType = (TlsContentType)reader.ReadByte();
                tlsPayload.Version = (TlsVersion)BitConverter.ToUInt16(reader.ReadBytes(2).Reverse().ToArray(), 0);

                ushort payloadLenght = BitConverter.ToUInt16(reader.ReadBytes(2).Reverse().ToArray(), 0);
                tlsPayload.PayloadLenght = payloadLenght;
                tlsPayload.Payload = reader.ReadBytes(payloadLenght);

                tlsPayload.AdditionalPayload = reader.ReadBytes((int)reader.BaseStream.Length - (int)reader.BaseStream.Position);
            }

            return tlsPayload;
        }

        public static bool IsTlsPayload(byte[] payload)
        {
            // try to parse the first 3 bytes of the tls payload
            // 1. check if the content type machtes the tls ones
            // 2. parse the version and check if it exists in the enum
            try
            {
                using MemoryStream memoryStream = new MemoryStream(payload);
                using BinaryReader reader = new BinaryReader(memoryStream);
                byte firstByte = reader.ReadByte();
                if ((firstByte >= 20 && firstByte <= 23)
                    || (firstByte == 255 && Enum.TryParse(typeof(TlsVersion), ((TlsVersion)reader.ReadUInt16()).ToString(), out _)))
                {
                    return true;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex); // ignored for now
            }


            return false;
        }

        public string GetString()
        {
            return Encoding.ASCII.GetString(Payload);
        }

        public override string ToString()
        {
            return $"{ContentType} {Version}: {PayloadLenght} bytes";
        }
    }
}