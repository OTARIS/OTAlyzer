using OTAlyzer.Common;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace OTAlyzer.AnalyticsCore.Analyzers.Searchers
{
    public abstract class HashSearcher : BasicSearcher
    {
        protected HashSearcher(Dictionary<string, List<string>> keywordList, StringComparison stringComparison = StringComparison.OrdinalIgnoreCase, Encoding encoding = null) : base(stringComparison, encoding)
        {
            KeywordList = ComputeHashes(keywordList);
        }

        protected abstract HashAlgorithm HashAlgorithm { get; }

        public Dictionary<string, List<string>> ComputeHashes(Dictionary<string, List<string>> keywordList)
        {
            Dictionary<string, List<string>> hashes = new Dictionary<string, List<string>>();

            foreach (KeyValuePair<string, List<string>> list in keywordList)
            {
                foreach (string keyword in list.Value)
                {
                    if (!keyword.StartsWith("$regex$"))
                    {
                        string hash = Utils.ByteArrayToString(HashAlgorithm.ComputeHash(Encoding.GetBytes(keyword)));

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