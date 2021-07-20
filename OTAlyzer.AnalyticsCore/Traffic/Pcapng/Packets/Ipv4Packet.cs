using OTAlyzer.AnalyticsCore.Traffic.Pcapng.Packets.Enums;
using OTAlyzer.AnalyticsCore.Traffic.Pcapng.Packets.Interfaces;
using System;
using System.IO;
using System.Linq;
using System.Net;

namespace OTAlyzer.AnalyticsCore.Traffic.Pcapng.Packets
{
    public class Ipv4Packet : ILayer3Packet
    {
        public byte DifferentiatedServiceField { get; private set; }

        public EthernetPacket EthernetPacket { get; private set; }

        public Ipv4Flags Flags { get; private set; }

        public int FragmentOffset { get; private set; }

        public ushort HeaderChecksum { get; private set; }

        public int HeaderLength { get; private set; }

        public ushort Identification { get; private set; }

        public byte[] IpAddressDestination { get; private set; }

        public byte[] IpAddressSource { get; private set; }

        public byte[] Payload { get; private set; }

        public IpProtocol Protocol { get; private set; }

        public ushort TotalLength { get; private set; }

        public byte Ttl { get; private set; }

        public int Version { get; private set; }

        public static bool FromText(string ipSrc, string ipDst, int ipHeaderLength, out Ipv4Packet ipv4Packet, EthernetPacket linkedEthernetPacket = null)
        {
            ipv4Packet = new Ipv4Packet { EthernetPacket = linkedEthernetPacket };

            try
            {
                ipv4Packet.IpAddressSource = IPAddress.Parse(ipSrc).GetAddressBytes();
                ipv4Packet.IpAddressDestination = IPAddress.Parse(ipDst).GetAddressBytes();
            }
            catch (System.FormatException)
            {
                // TODO: implement ipv6!
                ipv4Packet.IpAddressSource = IPAddress.Parse("0.0.0.0").GetAddressBytes();
                ipv4Packet.IpAddressDestination = IPAddress.Parse("0.0.0.0").GetAddressBytes();
            }
            ipv4Packet.HeaderLength = ipHeaderLength;

            return true;
        }

        public static bool FromBytes(byte[] input, out Ipv4Packet ipv4Packet, EthernetPacket linkedEthernetPacket = null)
        {
            if (input == null || input.Length < 20)
            {
                ipv4Packet = null;
                return false;
            }

            ipv4Packet = new Ipv4Packet { EthernetPacket = linkedEthernetPacket };

            using MemoryStream memoryStream = new MemoryStream(input);
            using BinaryReader reader = new BinaryReader(memoryStream);

            byte firstByte = reader.ReadByte();
            ipv4Packet.Version = (firstByte & 0xF0) >> 4;
            ipv4Packet.HeaderLength = (firstByte & 0x0F) * 4;
            ipv4Packet.DifferentiatedServiceField = reader.ReadByte();

            ipv4Packet.TotalLength = BitConverter.ToUInt16(reader.ReadBytes(2).Reverse().ToArray(), 0);
            ipv4Packet.Identification = BitConverter.ToUInt16(reader.ReadBytes(2).Reverse().ToArray(), 0);

            // we need to split this 2 bytes into 3 and 5 bits later
            byte[] ttlFragmentOffsetCombo = reader.ReadBytes(2);

            // flags and fragmentation offset are stored in one byte the first 3 bits are the flags
            ipv4Packet.Flags = (Ipv4Flags)(ttlFragmentOffsetCombo[0] & 0xE0);

            // the last 5 bits are the fragmentation offset
            byte[] fragmentOffsetBytes = new byte[] { (byte)(ttlFragmentOffsetCombo[0] & 0x1F), ttlFragmentOffsetCombo[1] };
            ipv4Packet.FragmentOffset = BitConverter.ToUInt16(fragmentOffsetBytes, 0);

            ipv4Packet.Ttl = reader.ReadByte();
            ipv4Packet.Protocol = (IpProtocol)reader.ReadByte();
            ipv4Packet.HeaderChecksum = BitConverter.ToUInt16(reader.ReadBytes(2).Reverse().ToArray(), 0);
            ipv4Packet.IpAddressSource = reader.ReadBytes(4);
            ipv4Packet.IpAddressDestination = reader.ReadBytes(4);
            ipv4Packet.Payload = reader.ReadBytes(ipv4Packet.TotalLength - (int)reader.BaseStream.Position);

            return true;
        }
    }
}