using OTAlyzer.AnalyticsCore.Analyzers.Objects.Enums;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace OTAlyzer.AnalyticsCore.Analyzers.Searchers
{
    public class SHA512Searcher : HashSearcher
    {
        public SHA512Searcher(Dictionary<string, List<string>> keywordList, StringComparison stringComparison = StringComparison.OrdinalIgnoreCase, Encoding encoding = null) : base(keywordList, stringComparison, encoding)
        {
        }

        public override FindingType FindingType => FindingType.SHA512_HASHED;

        protected override HashAlgorithm HashAlgorithm { get; } = SHA512.Create();
    }
}