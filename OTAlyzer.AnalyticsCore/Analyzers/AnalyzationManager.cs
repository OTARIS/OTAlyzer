using OTAlyzer.AnalyticsCore.Analyzers.Objects;
using OTAlyzer.AnalyticsCore.Analyzers.Objects.Enums;
using OTAlyzer.AnalyticsCore.Analyzers.Searchers;
using OTAlyzer.AnalyticsCore.Dns;
using OTAlyzer.AnalyticsCore.Location.Iplocation;
using OTAlyzer.AnalyticsCore.Traffic;
using OTAlyzer.AnalyticsCore.Traffic.Pcapng.Payloads;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;

namespace OTAlyzer.AnalyticsCore.Analyzers
{
    public class AnalyzationManager : IDisposable
    {
        private const int MAXPAYLOADLENGTH = 8000000;

        private Regex IpTruncate { get; } = new Regex("[^0-9.]", RegexOptions.Compiled);

        private SpeedmonitorIplocationClient IpLocationClient { get; set; }

        private DnsResolver DnsResolver { get; set; }

        private string[] Content { get; set; }

        /// <summary>
        /// Default constructor to setup a new AnalyzationManager
        /// </summary>
        /// <param name="keywordSearchers">Add all your IKeywordSearchers here</param>
        /// <param name="keywordlists">A list of keywords you want to search for</param>
        /// <param name="threadCount">The amount of Threads in the TreadPool</param>
        public AnalyzationManager(List<IKeywordSearcher> keywordSearchers, KeywordList keywordlists, int threadCount = 0)
        {
            IsActive = true;

            KeywordSearchers = keywordSearchers;
            KeywordList = keywordlists;
            
            // if no count is specified all processors are used
            threadCount = threadCount > 0 ? threadCount : Environment.ProcessorCount;
            ThreadCount = threadCount;

            Jobs = new ConcurrentQueue<AnalyzingJob>();
            ThreadPool = new List<Thread>();

            SetupThreadPool(threadCount);

            IpLocationClient = new SpeedmonitorIplocationClient();
            DnsResolver = new DnsResolver();
        }

        public delegate void FoundSomething(IAnalyzeable analyzeable, FindingType findingType, Dictionary<string, List<string>> keywords);

        /// <summary>
        /// Register for this callback to receive PayloadCombo and FindingType, in which the Keyword
        /// </summary>
        public event FoundSomething OnFoundSomething;

        public bool IsActive { get; private set; }

        public ConcurrentQueue<AnalyzingJob> Jobs { get; }

        public KeywordList KeywordList { get; }

        public List<IKeywordSearcher> KeywordSearchers { get; }

        public int ThreadCount { get; }

        public List<Thread> ThreadPool { get; }

        private IAnalyzeable[] Payloads { get; set; }

        /// <summary>
        /// Start the analyzation of PayloadCombos, make sure you added all IKeywordSearcher and
        /// Keywords to it.
        /// </summary>
        /// <param name="payloads">The PayloadCombos that will be analyzed</param>
        /// <param name="waitForExit">
        /// If set to true, the Thread will Sleep() until all Threads finished their Work
        /// </param>
        /// <param name="maxPayloadLength">
        /// Default: 8000000 (8MB)
        ///
        /// This increases performance very much, because all payloads bigger than this threshold
        /// won't be analyzed.
        ///
        /// Most of the time, data that is bigger than 8MB wont hold any valuable information,
        /// rather being some sort of media files.
        /// </param>
        public void Analyze(IEnumerable<IAnalyzeable> payloads, bool waitForExit = true, int maxPayloadLength = MAXPAYLOADLENGTH)
        {
            if (payloads == null)
            {
                return;
            }

            Payloads = payloads.Where(e => (e.Length < maxPayloadLength)).ToArray();

            int payLoadCount = Payloads.Length;

            if (payLoadCount == 0)
            {
                return;
            }

            Content = new string[payLoadCount];

            int jobsFinished = 0;

            for (int i = 0; i < payLoadCount; ++i)
            {
                bool payloadIsHttp = Payloads[i].GetType().Equals(typeof(HttpPayload));

                // Search for Keywords
                foreach (IKeywordSearcher keywordSearcher in KeywordSearchers)
                {
                    Content[i] = Payloads[i].GetString();

                    // if http, analyze headers as well
                    if (payloadIsHttp)
                    {
                        string httpHeaders = string.Join("\n", ((HttpPayload)Payloads[i]).HttpHeaders.Select(x => x.Key + ": " + x.Value).ToArray());
                        Content[i] = Content[i] + httpHeaders;
                    }

                    Jobs.Enqueue(new AnalyzingJob(i, keywordSearcher, () => Interlocked.Increment(ref jobsFinished)));
                }
            }

            while (waitForExit && jobsFinished < (payLoadCount * KeywordSearchers.Count))
            {
                Thread.Sleep(1);
            }
        }

        public void Dispose()
        {
            IsActive = false;
            foreach (Thread t in ThreadPool)
            {
                t.Join();
            }
        }

        /// <summary>
        /// <para>
        /// Use this Method after the Analyzation to add additional information to them:
        /// - Ip Location
        /// - Dns Lookups
        /// - Severity levels
        /// - Minimum supported TLS Version
        /// </para>
        /// <para>
        /// These information could not be retrieved during the analyzation part because it consists
        /// of blocking tasks that would slow it down.
        /// </para>
        /// </summary>
        /// <param name="findings">Your Findings to process</param>
        /// <param name="severityLevels"></param>
        /// <param name="isMitmAnalysis"></param>
        public void PostProcess(List<Finding> findings, Dictionary<string, Dictionary<string, int>> severityLevels, bool isMitmAnalysis)
        {
            Parallel.ForEach(findings, finding =>
            {
                SetSeverityLevel(finding, severityLevels);
                SetLocations(finding, isMitmAnalysis);
            });
            
            SetMinimumSupportedTlsVersion(findings);
        }
        
        private void SetupThreadPool(int threadCount)
        {
            for (int i = 0; i < threadCount; ++i)
            {
                Thread thread = new Thread(Work);
                ThreadPool.Add(thread);
                thread.Start();
            }
        }

        private void Work()
        {
            while (IsActive)
            {
                if (Jobs.TryDequeue(out AnalyzingJob job))
                {
                    Dictionary<string, List<string>> results = job.KeywordSearcher.Search(ref Content[job.PayloadId], false);

                    if (results.Any())
                    {
                        OnFoundSomething?.Invoke(Payloads[job.PayloadId], job.KeywordSearcher.FindingType, results);
                    }

                    job.Finish();
                }
                else
                {
                    Thread.Sleep(1);
                }
            }
        }

        private void SetSeverityLevel(Finding finding, Dictionary<string, Dictionary<string, int>> severityLevels)
        {
            // find highest severity level in finding
            int highest = 0;
            foreach (string matchedKeyword in finding.MatchedKeywords.Keys)
            {
                int severityLevel;
                if (finding.IsHttps)
                {
                    severityLevel = severityLevels[matchedKeyword]["encrypted"];
                }
                else
                {
                    severityLevel = severityLevels[matchedKeyword]["unencrypted"];
                }
                if (severityLevel > highest)
                {
                    highest = severityLevel;
                }
            }

            finding.SeverityLevel = highest;
        }

        private void SetLocations(Finding finding, bool isMitmAnalysis, bool enableIplocation = true)
        {
            Match match = IpTruncate.Match(finding.SourceIp);
            finding.SourceIp = match.Success ? finding.SourceIp.Substring(0, match.Index) : finding.SourceIp;
            match = IpTruncate.Match(finding.DestinationIp);
            finding.DestinationIp = match.Success ? finding.DestinationIp.Substring(0, match.Index) : finding.DestinationIp;

            // Source
            if (IPAddress.TryParse(finding.SourceIp, out IPAddress sourceIp))
            {
                if (enableIplocation)
                {
                    finding.SourceLocation = IpLocationClient.Get(sourceIp);
                }
            }

            if (isMitmAnalysis)
            {
                // strip port from ip generated by mitm
                finding.DestinationIp = finding.DestinationIp.Split(":")[0];
            }

            // Destination
            if (IPAddress.TryParse(finding.DestinationIp, out IPAddress destinationIp))
            {
                if (enableIplocation)
                {
                    if (isMitmAnalysis)
                    {
                        // mitm has local ips as the destination since it acts as a proxy, so lookup the url and then the ip

                        // format url for lookup (strip port and protocol)
                        finding.DestinationUrl = finding.DestinationUrl.Split(":")[1].Split("//")[1];

                        // lookup
                        IPAddress dstIp = DnsResolver.Get(finding.DestinationUrl);

                        if (dstIp != null)
                        {
                            finding.DestinationIp = dstIp.ToString();
                            destinationIp = dstIp;
                        }
                    }

                    finding.DestinationLocation = IpLocationClient.Get(destinationIp);
                }
            }
        }
        
        private void SetMinimumSupportedTlsVersion(List<Finding> findings)
        {
            string outfile = Path.GetTempFileName();
            List<string> scannedCiphers = new List<string>() { "SSLv1", "SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"};

            // create a set of unique hosts to enumerate
            IEnumerable<string> destinationIps = from finding in findings
                where finding.IsHttps
                select finding.DestinationIp;
            HashSet<string> uniqueDestinationIps = new HashSet<string>(destinationIps);
            
            // Start nmap to enumerate tls ciphers
            Process process = new Process();
            var timeoutSeconds = 30;
            process.StartInfo.FileName = "nmap"; 
            process.StartInfo.Arguments = $"--script-timeout {timeoutSeconds} --script ssl-enum-ciphers -T4 -p 443 -oX {outfile} {string.Join(" ", uniqueDestinationIps)}"; // TODO: what if it is another port for https?
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.CreateNoWindow = true;
            process.StartInfo.RedirectStandardOutput = true;
            process.Start();
            process.WaitForExit();
            
            // parse xml
            XmlDocument doc = new XmlDocument();
            doc.Load(outfile);
            Dictionary<string, string> minimumTlsVersions = new Dictionary<string, string>(); // maps ips to minimum tls version
            
            foreach (XmlNode hostNode in doc.DocumentElement.SelectNodes("/nmaprun/host"))
            {
                string currentHost = hostNode.SelectSingleNode("address").Attributes["addr"].InnerText;
                
                foreach (XmlNode node in hostNode.SelectNodes("ports/port/script/table"))
                {
                    // they are ordered, so just take the first tls version and break the loop
                    minimumTlsVersions.Add(currentHost, node.Attributes["key"]?.InnerText);
                    break;
                }
            }
            
            // add to findings
            foreach (Finding finding in findings)
            {
                if (minimumTlsVersions.TryGetValue(finding.DestinationIp, out string value))
                {
                    if (finding.IsHttps)
                    {
                        finding.MinimumSupportedTlsVersion = value;
                    }
                }
            }

            // clean up
            File.Delete(outfile);
        }
    }
}