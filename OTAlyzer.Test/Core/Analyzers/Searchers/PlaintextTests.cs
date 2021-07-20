using Microsoft.VisualStudio.TestTools.UnitTesting;
using OTAlyzer.AnalyticsCore.Analyzers.Objects;
using OTAlyzer.AnalyticsCore.Analyzers.Searchers;

namespace OTAlyzer.Test.Core.Analyzers.Searchers
{
    [TestClass]
    public class PlaintextTests
    {
        [TestMethod]
        public void SearchInlineData()
        {
            string sampleCorrectPayloadInline = "jggBasicXXgdfgd";
            KeywordList sampleKeywords = new KeywordList("{ sample: [ \"Test\", \"Basic\", \"1234\" ] }", string.Empty);

            PlaintextSearcher plaintextSearcher = new PlaintextSearcher(sampleKeywords.Keywords);
            Assert.IsTrue(plaintextSearcher.Search(ref sampleCorrectPayloadInline, false).Count > 0);
        }

        [TestMethod]
        public void SearchInvalidData()
        {
            string sampleWrongPayload = "jggBaseXXgdfgd";
            KeywordList sampleKeywords = new KeywordList("{ sample: [ \"Test\", \"Basic\", \"1234\" ] }", string.Empty);

            PlaintextSearcher plaintextSearcher = new PlaintextSearcher(sampleKeywords.Keywords);
            Assert.IsTrue(plaintextSearcher.Search(ref sampleWrongPayload, false).Count == 0);
        }

        [TestMethod]
        public void SearchValidData()
        {
            string sampleCorrectPayload = "Basic Textsample test 12143";
            KeywordList sampleKeywords = new KeywordList("{ sample: [ \"Test\", \"Basic\", \"1234\" ] }", string.Empty);

            PlaintextSearcher plaintextSearcher = new PlaintextSearcher(sampleKeywords.Keywords);
            Assert.IsTrue(plaintextSearcher.Search(ref sampleCorrectPayload, false).Count > 0);
        }
    }
}