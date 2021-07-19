namespace OTAlyzer.AnalyticsCore.Traffic.Pcapng.Packets.Interfaces
{
    public interface ILayer4Packet
    {
        byte[] Payload { get; }
    }
}