using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using OTAlyzer.AnalyticsCore.Analyzers.Objects.Enums;
using OTAlyzer.AnalyticsCore.Location.Iplocation.Objects;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace OTAlyzer.AnalyticsCore.Analyzers.Objects
{
    [StructLayout(LayoutKind.Sequential)]
    public class Finding
    {

        public Finding(string sourceUrl, string destinationUrl, FindingType findingType, Dictionary<string, List<string>> matchedKeywords, string fullPayload = "", Dictionary<string, List<string>> matchedKeywordsRaw = null)
        {
            MatchedKeywordsRaw = matchedKeywordsRaw;
            FindingType = findingType.ToString();
            MatchedKeywords = matchedKeywords;
            FullPayload = fullPayload;
            SourceUrl = sourceUrl;
            DestinationUrl = destinationUrl;
        }

        public int SeverityLevel { get; set; }

        public long FrameNumber { get; set; }

        public string Timestamp => DateTimeOffset.FromUnixTimeMilliseconds(TimestampMillis).DateTime.ToString();

        public long TimestampMillis { get; set; }

        public string EncryptionType { get; set; }

        public string FindingType { get; set; }

        public bool IsHttps { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string DestinationHostname { get; set; }

        public string DestinationUrl { get; set; }

        public string DestinationIp { get; set; }

        public ushort DestinationPort { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string DestinationMac { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string SourceHostname { get; set; }

        public string SourceUrl { get; set; }

        public string SourceIp { get; set; }

        public ushort SourcePort { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string SourceMac { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public IpLocation DestinationLocation { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public IpLocation SourceLocation { get; set; }
        
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string MinimumSupportedTlsVersion { get; set; }

        public Dictionary<string, List<string>> MatchedKeywords { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public Dictionary<string, List<string>> MatchedKeywordsRaw { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public Dictionary<string, string> HttpHeaders { get; set; }
        
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string FullPayload { get; set; }
    }
}