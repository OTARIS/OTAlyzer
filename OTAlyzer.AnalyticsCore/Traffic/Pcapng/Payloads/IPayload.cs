namespace OTAlyzer.AnalyticsCore.Traffic.Pcapng.Payloads
{
    public interface IPcapngPayload : IAnalyzeable
    {
        byte[] Payload { get; }
    }
}