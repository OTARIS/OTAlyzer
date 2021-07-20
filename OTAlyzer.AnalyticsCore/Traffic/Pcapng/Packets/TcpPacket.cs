using OTAlyzer.AnalyticsCore.Traffic.Pcapng.Packets.Enums;
using OTAlyzer.AnalyticsCore.Traffic.Pcapng.Packets.Interfaces;
using System;
using System.IO;
using System.Linq;

namespace OTAlyzer.AnalyticsCore.Traffic.Pcapng.Packets
{
    public class TcpPacket : ILayer4Packet
    {
        public uint AcknowledgementNumber { get; private set; }

        public ushort Checksum { get; private set; }

        public ushort DestinationPort { get; private set; }

        public TcpFlags Flags { get; private set; }

        public uint HeaderLength { get; private set; }

        public Ipv4Packet Ipv4Packet { get; private set; }

        public byte[] Options { get; private set; }

        public byte[] Payload { get; private set; }

        public uint RealtiveAcknowledgementNumber { get; set; }

        public uint RealtiveSequenceNumber { get; set; }

        public uint SequenceNumber { get; private set; }

        public ushort SourcePort { get; private set; }

        public ushort UrgentPointer { get; private set; }

        public ushort WindowSize { get; private set; }

        public static bool FromBytes(byte[] input, out TcpPacket tcpPacket, Ipv4Packet linkedIpv4Packet = null)
        {
            if (input == null || input.Length < 20)
            {
                tcpPacket = null;
                return false;
            }

            tcpPacket = new TcpPacket { Ipv4Packet = linkedIpv4Packet };

            using MemoryStream memoryStream = new MemoryStream(input);
            using BinaryReader reader = new BinaryReader(memoryStream);

            tcpPacket.SourcePort = BitConverter.ToUInt16(reader.ReadBytes(2).Reverse().ToArray(), 0);
            tcpPacket.DestinationPort = BitConverter.ToUInt16(reader.ReadBytes(2).Reverse().ToArray(), 0);
            tcpPacket.SequenceNumber = BitConverter.ToUInt32(reader.ReadBytes(4).Reverse().ToArray(), 0);
            tcpPacket.AcknowledgementNumber = BitConverter.ToUInt32(reader.ReadBytes(4).Reverse().ToArray(), 0);

            tcpPacket.HeaderLength = (uint)reader.ReadByte() / 4;
            tcpPacket.Flags = (TcpFlags)reader.ReadByte();
            tcpPacket.WindowSize = BitConverter.ToUInt16(reader.ReadBytes(2).Reverse().ToArray(), 0);
            tcpPacket.Checksum = BitConverter.ToUInt16(reader.ReadBytes(2).Reverse().ToArray(), 0);
            tcpPacket.UrgentPointer = BitConverter.ToUInt16(reader.ReadBytes(2).Reverse().ToArray(), 0);
            tcpPacket.Options = reader.ReadBytes((int)tcpPacket.HeaderLength - (int)reader.BaseStream.Position);

            tcpPacket.Payload = reader.ReadBytes((int)reader.BaseStream.Length - (int)reader.BaseStream.Position);

            return true;
        }
        public static bool FromText(ushort srcPort, ushort dstPort, uint tcpSeq, uint tcpAck, out TcpPacket tcpPacket, Ipv4Packet linkedIpv4Packet = null)
        {
            tcpPacket = new TcpPacket { Ipv4Packet = linkedIpv4Packet };

            tcpPacket.SourcePort = srcPort;
            tcpPacket.DestinationPort = dstPort;
            tcpPacket.SequenceNumber = tcpSeq;
            tcpPacket.AcknowledgementNumber = tcpAck;

            // TODO: parse other values when coming from tshark

            return true;
        }
    }
}