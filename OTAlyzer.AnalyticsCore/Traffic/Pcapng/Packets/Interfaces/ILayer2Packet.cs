namespace OTAlyzer.AnalyticsCore.Traffic.Pcapng.Packets.Interfaces
{
    public interface ILayer2Packet
    {
        byte[] Payload { get; }
    }
}