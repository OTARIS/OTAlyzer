using OTAlyzer.AnalyticsCore.AppStore.Interfaces;

namespace OTAlyzer.AnalyticsCore.AppStore.Android.Playstore
{
    public class PlaystoreEntry : IStoreEntry
    {
        public string Base64Image { get; set; }

        public string Currency { get; set; }

        public string Developer { get; set; }

        public string DeveloperUrl { get; set; }

        // only used for EntityFramework
        public string Id { get; set; }

        public string LastUpdate { get; set; }

        public string LastVersion { get; set; }

        public string MinimalOsVersion { get; set; }

        public string Name { get; set; }

        public double Price { get; set; }

        public double Rating { get; set; }

        public int TotalRatings { get; set; }

        public string Url { get; set; }

        public string Usk { get; set; }
    }
}