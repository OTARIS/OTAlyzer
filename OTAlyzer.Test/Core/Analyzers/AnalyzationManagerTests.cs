using Microsoft.VisualStudio.TestTools.UnitTesting;
using OTAlyzer.AnalyticsCore.Analyzers;
using OTAlyzer.AnalyticsCore.Analyzers.Objects;
using OTAlyzer.AnalyticsCore.Analyzers.Searchers;
using OTAlyzer.AnalyticsCore.Traffic;
using OTAlyzer.AnalyticsCore.Traffic.Misc;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace OTAlyzer.Test.Core.Analyzers
{
    [TestClass]
    public class AnalyzationManagerTests
    {
        [TestMethod]
        public void SampleStringAnalysis()
        {
            string samplePayload = "Hello this is a sample text containing only one of the Keywords in this TEST";

            KeywordList keywords = new KeywordList("{ sample: [\"Test\"] }", string.Empty);

            List<IKeywordSearcher> keywordSearchers = new List<IKeywordSearcher>
            {
                new PlaintextSearcher(keywords.Keywords, StringComparison.OrdinalIgnoreCase),
                new MD5Searcher(keywords.Keywords, StringComparison.OrdinalIgnoreCase),
                new Base64Searcher(keywords.Keywords, StringComparison.OrdinalIgnoreCase)
            };

            ConcurrentBag<Dictionary<string, List<string>>> findings = new ConcurrentBag<Dictionary<string, List<string>>>();

            List<IAnalyzeable> payloads = new List<IAnalyzeable> { new AnalyzeableString(samplePayload) };

            AnalyzationManager analyzationManager = new AnalyzationManager(keywordSearchers, keywords);
            analyzationManager.OnFoundSomething += (_, __, keyword) => findings.Add(keyword);

            Assert.AreEqual(Environment.ProcessorCount, analyzationManager.ThreadCount);

            analyzationManager.Analyze(payloads);

            Assert.IsTrue(findings.Any(e => e.ContainsKey("sample")));
        }
    }
}