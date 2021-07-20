using OTAlyzer.AnalyticsCore.Analyzers.Objects.Enums;
using System;
using System.Collections.Generic;

namespace OTAlyzer.AnalyticsCore.Analyzers.Searchers
{
    public class PlaintextSearcher : BasicSearcher
    {
        public PlaintextSearcher(Dictionary<string, List<string>> keywordList, StringComparison stringComparison = StringComparison.OrdinalIgnoreCase) : base(stringComparison)
        {
            KeywordList = keywordList;
        }

        public override FindingType FindingType => FindingType.PLAIN_TEXT;
    }
}