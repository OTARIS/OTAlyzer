using Newtonsoft.Json;

namespace OTAlyzer.AnalyticsCore.Location.Iplocation.Objects
{
    public class IpLocation
    {
        [JsonProperty("City")]
        public string City { get; set; }

        [JsonProperty("ContinentCode")]
        public string Continent { get; set; }

        [JsonProperty("ContinentName")]
        public string ContinentName { get; set; }

        [JsonProperty("CountryCodeIso3166Alpha2")]
        public string Country { get; set; }

        [JsonProperty("CountryName")]
        public string CountryName { get; set; }

        [JsonIgnore]
        public int Id { get; set; }

        [JsonProperty("IpAddress")]
        public string Ip { get; set; }

        [JsonProperty("Latitude")]
        public double Latitude { get; set; }

        [JsonProperty("Longitude")]
        public double Longitude { get; set; }

        [JsonProperty("Organization")]
        public string Organisation { get; set; }

        [JsonProperty("PostalCode")]
        public string PostalCode { get; set; }

        [JsonProperty("RegionCode")]
        public string RegionCode { get; set; }

        [JsonProperty("RegionName")]
        public string RegionName { get; set; }
    }
}