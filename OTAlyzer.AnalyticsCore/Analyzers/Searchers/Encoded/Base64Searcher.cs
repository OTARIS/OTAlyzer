using OTAlyzer.AnalyticsCore.Analyzers.Objects.Enums;
using System;
using System.Collections.Generic;
using System.Text;

namespace OTAlyzer.AnalyticsCore.Analyzers.Searchers
{
    public class Base64Searcher : BasicSearcher
    {
        public Base64Searcher(Dictionary<string, List<string>> keywordList, StringComparison stringComparison = StringComparison.OrdinalIgnoreCase, Encoding encoding = null) : base(stringComparison, encoding)
        {
            KeywordList = BuildStrings(keywordList);
        }

        public override FindingType FindingType => FindingType.BASE64_ENCODED;

        public Dictionary<string, List<string>> BuildStrings(Dictionary<string, List<string>> keywordList)
        {
            Dictionary<string, List<string>> hashes = new Dictionary<string, List<string>>();

            foreach (KeyValuePair<string, List<string>> list in keywordList)
            {
                foreach (string keyword in list.Value)
                {
                    if (!keyword.StartsWith("$regex$"))
                    {
                        string hash = Convert.ToBase64String(Encoding.GetBytes(keyword));

                        if (!string.IsNullOrEmpty(hash))
                        {
                            if (!hashes.ContainsKey(list.Key))
                            {
                                hashes.Add(list.Key, new List<string>());
                            }

                            hashes[list.Key].Add(hash);
                        }
                    }
                }
            }

            return hashes;
        }
    }
}