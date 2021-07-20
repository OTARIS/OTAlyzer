using OTAlyzer.AnalyticsCore.Analyzers.Objects.Enums;
using System.Collections.Generic;

namespace OTAlyzer.AnalyticsCore.Analyzers.Searchers
{
    public interface IKeywordSearcher
    {
        FindingType FindingType { get; }

        Dictionary<string, List<string>> Search(ref string input, bool allowDuplicates);
    }
}