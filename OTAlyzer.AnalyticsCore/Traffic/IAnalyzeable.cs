namespace OTAlyzer.AnalyticsCore.Traffic
{
    public interface IAnalyzeable
    {
        int Length { get; }

        string GetString();
    }
}