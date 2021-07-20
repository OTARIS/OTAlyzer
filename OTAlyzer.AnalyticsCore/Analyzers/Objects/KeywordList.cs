using Newtonsoft.Json;
using System.Collections.Generic;

namespace OTAlyzer.AnalyticsCore.Analyzers.Objects
{
    public class KeywordList
    {
        public KeywordList(string jsonKeywords, string jsonSeverityLevels)
        {
            Keywords = JsonConvert.DeserializeObject<Dictionary<string, List<string>>>(jsonKeywords);
            SeverityLevels = JsonConvert.DeserializeObject<Dictionary<string, Dictionary<string, int>>>(jsonSeverityLevels);
        }

        public KeywordList()
        {
            Keywords = new Dictionary<string, List<string>>();
            SeverityLevels = new Dictionary<string, Dictionary<string, int>>();
        }

        public Dictionary<string, List<string>> Keywords { get; }
        public Dictionary<string, Dictionary<string, int>> SeverityLevels { get; }

        public void AddSeverityLevel(string keyword, int unencryptedSeverity, int encryptedSeverity)
        {
            SeverityLevels.Add(
                keyword, new Dictionary<string, int>
                {
                    { "encrypted", encryptedSeverity },
                    { "unencrypted", unencryptedSeverity}
                }
            );
        }
    }
}
