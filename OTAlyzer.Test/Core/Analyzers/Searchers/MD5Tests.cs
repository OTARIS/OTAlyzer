using Microsoft.VisualStudio.TestTools.UnitTesting;
using OTAlyzer.AnalyticsCore.Analyzers.Objects;
using OTAlyzer.AnalyticsCore.Analyzers.Searchers;

namespace OTAlyzer.Test.Core.Analyzers.Searchers
{
    [TestClass]
    public class MD5Tests
    {
        [TestMethod]
        public void InvalidPayload()
        {
            string sampleData = "test";
            KeywordList sampleKeywords = new KeywordList("{ sample: [ \"Test\", \"testmd5\", \"1234\" ] }", string.Empty);

            MD5Searcher md5Searcher = new MD5Searcher(sampleKeywords.Keywords);
            Assert.IsTrue(md5Searcher.Search(ref sampleData, false).Count == 0);
        }

        [TestMethod]
        public void ValidPayload()
        {
            string sampleData = "32269ae63a25306bb46a03d6f38bd2b7";
            KeywordList sampleKeywords = new KeywordList("{ sample: [ \"Test\", \"testmd5\", \"1234\" ] }", string.Empty);

            MD5Searcher md5Searcher = new MD5Searcher(sampleKeywords.Keywords);
            Assert.IsTrue(md5Searcher.Search(ref sampleData, false).Count > 0);
        }

        [TestMethod]
        public void ValidPayloadWithAdditionalData()
        {
            string sampleData = "xxx32269ae63a25306bb46a03d6f38bd2b7zzz";
            KeywordList sampleKeywords = new KeywordList("{ sample: [ \"Test\", \"testmd5\", \"1234\" ] }", string.Empty);

            MD5Searcher md5Searcher = new MD5Searcher(sampleKeywords.Keywords);
            Assert.IsTrue(md5Searcher.Search(ref sampleData, false).Count > 0);
        }
    }
}