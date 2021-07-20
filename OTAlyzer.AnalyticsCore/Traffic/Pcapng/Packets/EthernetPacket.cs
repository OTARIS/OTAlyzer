using OTAlyzer.AnalyticsCore.Traffic.Pcapng.Packets.Enums;
using OTAlyzer.AnalyticsCore.Traffic.Pcapng.Packets.Interfaces;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using OTAlyzer.Common;

namespace OTAlyzer.AnalyticsCore.Traffic.Pcapng.Packets
{
    public class EthernetPacket : ILayer2Packet
    {
        public long FrameNumber { get; set; }

        public string Timestamp { get; set; }

        public EtherType EtherType { get; set; }

        public string MacAddressDestination { get; set; }

        public string MacAddressSource { get; set; }

        public byte[] Payload { get; set; }

        public long GetTimestampInMilliseconds()
        {
            if (DateTime.TryParse(Timestamp, out DateTime ts))
            {
                return (long)ts.ToUniversalTime().Subtract(new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalMilliseconds;
            }
            else
            {
                // TODO: inspect this, maybes export from tshark in utc?
                // sometimes date parsing fails on windows because of weird
                // time formats like: "Sep  3, 2020 08:19:12.550084096 Mitteleuropäische Sommerzeit"
                return -1;
            }
        }

        public static bool FromText(long FrameNumber, string macSrc, string macDst, string timestamp, out EthernetPacket ethernetPacket)
        {
            ethernetPacket = new EthernetPacket
            {
                // TODO: other fields from tshark
                FrameNumber = FrameNumber,
                Timestamp = timestamp,
                MacAddressDestination = macDst,
                MacAddressSource = macSrc
            };

            return true;
        }

        public static bool FromBytes(byte[] input, out EthernetPacket ethernetPacket)
        {
            if (input == null || input.Length < 14)
            {
                ethernetPacket = null;
                return false;
            }

            ethernetPacket = new EthernetPacket();

            using MemoryStream memoryStream = new MemoryStream(input);
            using BinaryReader reader = new BinaryReader(memoryStream);

            ethernetPacket.MacAddressDestination = Utils.MacAddressToString(reader.ReadBytes(6));
            ethernetPacket.MacAddressSource = Utils.MacAddressToString(reader.ReadBytes(6));

            ethernetPacket.EtherType = (EtherType)BitConverter.ToUInt16(reader.ReadBytes(2).Reverse().ToArray(), 0);
            ethernetPacket.Payload = reader.ReadBytes((int)reader.BaseStream.Length - (int)reader.BaseStream.Position);

            return true;
        }
    }
}