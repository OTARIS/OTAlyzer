using Microsoft.VisualStudio.TestTools.UnitTesting;
using OTAlyzer.AnalyticsCore.Analyzers.Objects;
using OTAlyzer.AnalyticsCore.Analyzers.Searchers;

namespace OTAlyzer.Test.Core.Analyzers.Searchers
{
    [TestClass]
    public class Base64Tests
    {
        [TestMethod]
        public void InvalidBase64Encoding()
        {
            string sampleWrongPayload = "Base";
            KeywordList sampleKeywords = new KeywordList("{ sample: [ \"Test\", \"228VSR:45068a7637404fc798a208d6c1f29e4f\", \"1234\" ] }", string.Empty);

            Base64Searcher base64Searcher = new Base64Searcher(sampleKeywords.Keywords);
            Assert.IsTrue(base64Searcher.Search(ref sampleWrongPayload, false).Count == 0);
        }

        [TestMethod]
        public void ValidBase64Encoding()
        {
            string sampleCorrectPayload = "Basic MjI4VlNSOjQ1MDY4YTc2Mzc0MDRmYzc5OGEyMDhkNmMxZjI5ZTRm";
            KeywordList sampleKeywords = new KeywordList("{ sample: [ \"Test\", \"228VSR:45068a7637404fc798a208d6c1f29e4f\", \"1234\" ] }", string.Empty);

            Base64Searcher base64Searcher = new Base64Searcher(sampleKeywords.Keywords);
            Assert.IsTrue(base64Searcher.Search(ref sampleCorrectPayload, false).Count > 0);
        }
    }
}