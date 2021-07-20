using Microsoft.VisualStudio.TestTools.UnitTesting;
using OTAlyzer.AnalyticsCore.Dns;
using System.Net;

namespace OTAlyzer.Test.Core.Analyzers.Searchers
{
    [TestClass]
    public class DnsTests
    {
        [TestMethod]
        public void FullDnsOneOneOneOne()
        {
            const string sampleDns = "one.one.one.one";
            IPAddress ip = Dns.GetHostAddresses(sampleDns)[0];
            Assert.AreEqual(sampleDns, Dns.GetHostEntry(ip).HostName);

            ReverseDnsResolver reverseDnsResolver = new ReverseDnsResolver();
            string rdns = reverseDnsResolver.Get(ip);

            Assert.AreEqual(sampleDns, rdns);
        }
    }
}