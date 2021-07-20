namespace OTAlyzer.AnalyticsCore.AppStore.Interfaces
{
    public interface IStoreEntry
    {
        string Base64Image { get; set; }

        string Name { get; set; }
    }
}