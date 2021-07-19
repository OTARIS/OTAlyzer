using OTAlyzer.AnalyticsCore.Analyzers.Objects.Enums;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace OTAlyzer.AnalyticsCore.Analyzers.Searchers
{
    public class MD5Searcher : HashSearcher
    {
        public MD5Searcher(Dictionary<string, List<string>> keywordList, StringComparison stringComparison = StringComparison.OrdinalIgnoreCase, Encoding encoding = null) : base(keywordList, stringComparison, encoding)
        {
        }

        public override FindingType FindingType => FindingType.MD5_HASHED;

        protected override HashAlgorithm HashAlgorithm { get; } = MD5.Create();
    }
}