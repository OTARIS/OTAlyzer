namespace OTAlyzer.AnalyticsCore.Traffic.Pcapng.Packets.Interfaces
{
    public interface ILayer3Packet
    {
        byte[] Payload { get; }
    }
}