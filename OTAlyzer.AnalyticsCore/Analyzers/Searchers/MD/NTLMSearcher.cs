using Org.BouncyCastle.Crypto.Digests;
using OTAlyzer.AnalyticsCore.Analyzers.Objects.Enums;
using OTAlyzer.Common;
using System;
using System.Collections.Generic;
using System.Text;

namespace OTAlyzer.AnalyticsCore.Analyzers.Searchers
{
    public class NTLMSearcher : BasicSearcher
    {
        public NTLMSearcher(Dictionary<string, List<string>> keywordList, StringComparison stringComparison = StringComparison.OrdinalIgnoreCase, Encoding encoding = null) : base(stringComparison)
        {
            KeywordList = ComputeHashes(keywordList);
        }

        public override FindingType FindingType => FindingType.NTLM_HASHED;

        public static byte[] NTHashAsBytes(string keyword)
        {
            MD4Digest md = new MD4Digest();
            byte[] unicodeKeyword = Encoding.Convert(Encoding.ASCII, Encoding.Unicode, Encoding.ASCII.GetBytes(keyword));

            md.BlockUpdate(unicodeKeyword, 0, unicodeKeyword.Length);
            byte[] hash = new byte[16];
            md.DoFinal(hash, 0);

            return hash;
        }

        public Dictionary<string, List<string>> ComputeHashes(Dictionary<string, List<string>> keywordList)
        {
            Dictionary<string, List<string>> hashes = new Dictionary<string, List<string>>();

            foreach (KeyValuePair<string, List<string>> list in keywordList)
            {
                foreach (string keyword in list.Value)
                {
                    string hash = Utils.ByteArrayToString(NTHashAsBytes(keyword));

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

            return hashes;
        }
    }
}