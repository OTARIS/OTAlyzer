using OTAlyzer.AnalyticsCore.Analyzers.Objects.Enums;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace OTAlyzer.AnalyticsCore.Analyzers.Searchers
{
    public class SHA384Searcher : HashSearcher
    {
        public SHA384Searcher(Dictionary<string, List<string>> keywordList, StringComparison stringComparison = StringComparison.OrdinalIgnoreCase, Encoding encoding = null) : base(keywordList, stringComparison, encoding)
        {
        }

        public override FindingType FindingType => FindingType.SHA384_HASHED;

        protected override HashAlgorithm HashAlgorithm { get; } = SHA384.Create();
    }
}