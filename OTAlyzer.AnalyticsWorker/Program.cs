using Newtonsoft.Json;
using OTAlyzer.AnalyticsCore.Analyzers;
using OTAlyzer.AnalyticsCore.Analyzers.Objects;
using OTAlyzer.AnalyticsCore.Analyzers.Objects.Enums;
using OTAlyzer.AnalyticsCore.Analyzers.Searchers;
using OTAlyzer.AnalyticsCore.Dns;
using OTAlyzer.AnalyticsCore.Misc;
using OTAlyzer.AnalyticsCore.Traffic.Mitmproxy;
using OTAlyzer.AnalyticsCore.Traffic.Mitmproxy.Blocks;
using OTAlyzer.AnalyticsCore.Traffic.Pcapng.Payloads;
using OTAlyzer.AnalyticsWorker.Options;
using OTAlyzer.Common;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace OTAlyzer.AnalyticsWorker
{
    internal static class Program
    {
        private static bool IsMitmAnalysis = false;

        private static int nEncryptedFindings = 0;

        private enum OtalyzerExit : int
        {
            SUCCESS,
            WRONG_ARGUMENTS_SUPPLIED,
            NO_MATCHES_FOUND,
            NO_PAYLOADS_FOUND,
            MITM_DUMP_FAILED,
            MISSING_SEVERITY_LEVELS,
            CI_FAILED,
            WRONG_EXTENSION,
            INVALID_SSLKEYLOG_FILE,
            TSHARK_FAILED,
            TSHARK_PARSING_FAILED,
        }

        public static void DisplayBanner()
        {
            Console.WriteLine(" _____  ____   __    __   _  _  ____  ____  ____ ");
            Console.WriteLine("(  _  )(_  _) /__\\  (  ) ( \\/ )(_   )( ___)(  _ \\");
            Console.WriteLine(" )(_)(   )(  /(__)\\  )(__ \\  /  / /_  )__)  )   /");
            Console.WriteLine("(_____) (__)(__)(__)(____)(__) (____)(____)(_)\\_)");
            Console.WriteLine("\t>>> otaris traffic analyzer");
            Console.WriteLine();
        }

        public static void DisplayUsage()
        {
            Console.WriteLine("Minimal usage: otalyzer -k [KEYWORD_FILE] -s [SEVERITY_FILE] -p [CAPTURE_FILE] --filename [OUTFILE]");
            Console.WriteLine();
            Console.WriteLine("Mandatory parameters:");
            Console.WriteLine("-k | --keyword-file [file]: File containing search-keywords");
            Console.WriteLine("-s | --severity-level-file [file]: File specifiying the severity of each finding");
            Console.WriteLine("-p | --pcap-file [file]: The .pcap[ng]/mitmproxy file to analyze");
            Console.WriteLine("--filename [filename]: The name of the output file");
            Console.WriteLine();
            Console.WriteLine("Other options:");
            Console.WriteLine("--tls [sslkeylogfile]: Use TLS-decryption using the credentials supplied in the file");
            Console.WriteLine("--severity-threshold [0-9] | Exit with error on a finding with a severity level higher than the threshold set. To be used for CI pipelines");
            Console.WriteLine("--blacklist [filename{,filename,filename}] | Uses the files specified as blacklists for urls (e.g. trackers) and checks for plaintext occurences (to be used with large lists of URLs/IPs)");
            Console.WriteLine("-h | --help | --usage: Display this message");
            Console.WriteLine();
            Console.WriteLine("Example usage: otalyzer --filename analysis -k keywords/keywords.txt -s keywords/severity.txt -p test.pcapng --tls sslkey.log");
            Console.WriteLine();
            Console.WriteLine("You can use regex in a keyword with the $regex$ prefix.");
            Console.WriteLine("Example keyword file: { \"Post-Requests\":[\"POST\"], \"Credentials\":[\"$regex$.*@mail[.]com\"] }");
            Console.WriteLine("An example severity level file could look like this: {\"Credentials\": { \"encrypted\": 2, \"unencrypted\": 10 } }");
        }

        public static int Main(string[] args)
        {
            if (!OptionsBuilder.TryParseCommandLineArguments(args, out OtalyzerOptions otalyzerOptions))
            {
                return (int)OtalyzerExit.WRONG_ARGUMENTS_SUPPLIED;
            }

            DisplayBanner();

            string jsonKeywords = File.ReadAllText(otalyzerOptions.KeywordListFile);
            string jsonSeverityLevels = File.ReadAllText(otalyzerOptions.SeverityLevelFile);

            KeywordList keywordList = new KeywordList(jsonKeywords, jsonSeverityLevels);
            keywordList.AddSeverityLevel("Tracking pixel", 5, 2); 
            keywordList.AddSeverityLevel("Blacklist match", 5, 2); 

            // Check for severity levels
            //---------------------------------------------------------------------------------------------------------
            foreach (string key in keywordList.Keywords.Keys)
            {
                if (!keywordList.SeverityLevels.ContainsKey(key))
                {
                    Logger.LogNegative($"Your severity file misses a definition for the severity of '{key}'");
                    return (int)OtalyzerExit.MISSING_SEVERITY_LEVELS;
                }
            }

            // Parse blacklists if supplied
            //---------------------------------------------------------------------------------------------------------
            Dictionary<string, List<string>> blacklistKeywords = new Dictionary<string, List<string>>();

            if (otalyzerOptions.BlacklistFiles?.Any() == true)
            {
                foreach (string blacklistFile in otalyzerOptions.BlacklistFiles)
                {
                    List<string> blacklisted = File.ReadAllLines(blacklistFile).ToList<string>();
                    blacklistKeywords.Add(blacklistFile, blacklisted);
                }
            }

            // Setup
            //---------------------------------------------------------------------------------------------------------
            List<IKeywordSearcher> keywordSearchers = new List<IKeywordSearcher>
            {
                new PlaintextSearcher(keywordList.Keywords, StringComparison.OrdinalIgnoreCase),
                new Base64Searcher(keywordList.Keywords, StringComparison.OrdinalIgnoreCase),
                new MD2Searcher(keywordList.Keywords, StringComparison.OrdinalIgnoreCase),
                new NTLMSearcher(keywordList.Keywords, StringComparison.OrdinalIgnoreCase),
                new MD5Searcher(keywordList.Keywords, StringComparison.OrdinalIgnoreCase),
                new SHA1Searcher(keywordList.Keywords, StringComparison.OrdinalIgnoreCase),
                new SHA256Searcher(keywordList.Keywords, StringComparison.OrdinalIgnoreCase),
                new SHA384Searcher(keywordList.Keywords, StringComparison.OrdinalIgnoreCase),
                new SHA512Searcher(keywordList.Keywords, StringComparison.OrdinalIgnoreCase),
                new UrlEncodingSearcher(keywordList.Keywords, StringComparison.OrdinalIgnoreCase)
            };

            ConcurrentBag<Finding> findings = new ConcurrentBag<Finding>();

            MitmAnalyzer mitmAnalyzer = new MitmAnalyzer();
            TsharkWrapper pcapAnalyzer = new TsharkWrapper(otalyzerOptions.TrafficCaptureFile, otalyzerOptions.DecryptTls, otalyzerOptions.Sslkeylogfile);

            using AnalyzationManager analyzationManager = new AnalyzationManager(keywordSearchers, keywordList);
            // forward the callback into FindingBuilder.Build to create findings
            analyzationManager.OnFoundSomething += (payload, findingType, keywords)
                => findings.Add(FindingBuilder.Build(payload, findingType, keywords));

            // Parse packets
            //---------------------------------------------------------------------------------------------------------
            int ret = ParsePacketPayloads(pcapAnalyzer, mitmAnalyzer, otalyzerOptions);

            if (ret != 0)
            {
                switch (ret)
                {
                case 8:
                    Logger.LogNegative($"Packets could not be parsed because the provided SSL keylog file is not valid.");
                    break;
                default:
                    Logger.LogNegative($"Packets could not be parsed: OTAlyzer returned non-zero exit code: {ret}");
                    break;
                }
                return ret;
            }

            // Processing blacklist
            //---------------------------------------------------------------------------------------------------------
            Logger.Log("Checking for blacklisted hosts");

            long blacklistedHostsTime = Utils.ExecutionTimeMs(() =>
            {
                // Check if any destination hosts match the urls in the blacklist
                CheckForBlacklistedHosts(pcapAnalyzer, mitmAnalyzer, blacklistKeywords, findings);
            });

            Logger.Log($"-> took {blacklistedHostsTime}ms...\n");

            // Analyze payloads
            //---------------------------------------------------------------------------------------------------------
            Logger.Log("Starting analyzation");

            long analyzationTime = Utils.ExecutionTimeMs(() =>
            {
                analyzationManager.Analyze(pcapAnalyzer.FoundPayloads);
                analyzationManager.Analyze(mitmAnalyzer.MitmBlocks);
            });

            Logger.Log($"-> took {analyzationTime}ms...\n");

            // Filter the findings
            //---------------------------------------------------------------------------------------------------------
            Logger.Log("Filtering duplicates");

            List<Finding> filteredFindings = null;
            long filterTime = Utils.ExecutionTimeMs(() =>
            {
                filteredFindings = FilterFindings(findings);
            });

            Logger.Log($"-> took {filterTime}ms...\n");

            if (filteredFindings.Count == 0)
            {
                Logger.LogAlert("No matches found");

                if (!otalyzerOptions.InCiPipeline)
                {
                    return (int)OtalyzerExit.NO_MATCHES_FOUND;
                }
            }

            // PostProcess
            //---------------------------------------------------------------------------------------------------------
            Logger.Log("PostProcessing");
            long postprocessTime = PostProcess(filteredFindings, analyzationManager, keywordList.SeverityLevels);
            Logger.Log($"-> took {postprocessTime}ms...\n");

            // Display results
            //---------------------------------------------------------------------------------------------------------
            Logger.LogPositive($"Found {filteredFindings.Count} matches to supplied keywords");
            Logger.LogPositive($"{nEncryptedFindings} TLS-encrypted / {filteredFindings.Count - nEncryptedFindings} unencrypted");

            IEnumerable<Finding> outputData = filteredFindings.OrderBy(e => e.DestinationUrl);
            File.WriteAllText($"{otalyzerOptions.OutputFile}", JsonConvert.SerializeObject(outputData, Formatting.Indented));
            Logger.LogPositive($"Results saved to {otalyzerOptions.OutputFile}");

            if (otalyzerOptions.InCiPipeline && CiShouldFail(otalyzerOptions.Threshold, filteredFindings))
            {
                Logger.LogAlert("FAILED! See report for details!");
                return (int)OtalyzerExit.CI_FAILED;
            }

            return 0;
        }

        private static void CheckForBlacklistedHosts(TsharkWrapper pcapAnalyzer, MitmAnalyzer mitmAnalyzer, Dictionary<string, List<string>> blacklistKeywords, ConcurrentBag<Finding> findings)
        {
            ReverseDnsResolver reverseDnsResolver = new ReverseDnsResolver();

            // PCAP
            if (pcapAnalyzer.FoundPayloads?.Any() == true)
            {
                // do reverse DNS resolving to enable blacklist filtering
                Parallel.ForEach(pcapAnalyzer.FoundPayloads.OfType<HttpPayload>(), new ParallelOptions() { MaxDegreeOfParallelism = 64 }, pl =>
                {
                    IPAddress sourceIp = new IPAddress(pl.TcpPacket.Ipv4Packet.IpAddressDestination);
                    IPAddress destinationIp = new IPAddress(pl.TcpPacket.Ipv4Packet.IpAddressDestination);

                    string host = reverseDnsResolver.Get(destinationIp);

                    foreach (KeyValuePair<string, List<string>> blacklist in blacklistKeywords)
                    {
                        foreach (string url in blacklist.Value)
                        {
                            // add to findings if in blacklist
                            if (!string.IsNullOrWhiteSpace(host) && host.Contains(url))
                            {
                                Finding f = new Finding(
                                    sourceIp.ToString(),
                                    destinationIp.ToString(),
                                    FindingType.PLAIN_TEXT,
                                    new Dictionary<string, List<string>>() { { "Blacklist match", new List<string>() { $"Destination URL {host} is blacklisted ({url})" } } }
                                )
                                {
                                    SourceIp = sourceIp.ToString(),
                                    DestinationIp = destinationIp.ToString(),
                                    FrameNumber = pl.TcpPacket.Ipv4Packet.EthernetPacket.FrameNumber
                                };

                                findings.Add(f);
                            }
                        }
                    }
                });
            }

            // MITM
            if (mitmAnalyzer.MitmBlocks?.Any() == true)
            {
                Parallel.ForEach(mitmAnalyzer.MitmBlocks.OfType<MitmBlock>(), new ParallelOptions() { MaxDegreeOfParallelism = 64 }, pl =>
                {
                    string destinationIp = (string)pl.ServerConnection["address"]["host"];

                    IPAddress ip = IPAddress.Parse(destinationIp);
                    string host = reverseDnsResolver.Get(ip);

                    foreach (KeyValuePair<string, List<string>> blacklist in blacklistKeywords)
                    {
                        foreach (string url in blacklist.Value)
                        {
                            // add to findings if in blacklist
                            if (!string.IsNullOrWhiteSpace(host) && host.Contains(url))
                            {
                                Finding f = FindingBuilder.BuildFromMitmBlock(pl, FindingType.PLAIN_TEXT, new Dictionary<string, List<string>>() { { "Blacklist match", new List<string>() { url } } });
                                findings.Add(f);
                            }
                        }
                    }
                });
            }
        }

        private static bool CiShouldFail(int threshhold, IEnumerable<Finding> findings)
        {
            bool ciShouldFail = false;

            foreach (Finding f in findings)
            {
                if (f.SeverityLevel > threshhold)
                {
                    ciShouldFail = true;
                    Logger.LogAlert($"{string.Join(", ", f.MatchedKeywords.Keys)} -- {f.SourceIp}->{f.DestinationIp}. Encryption:{f.FindingType}. Https:{f.IsHttps} -- Severity: {f.SeverityLevel}!");
                }
            }

            return ciShouldFail;
        }

        private static List<Finding> FilterFindings(ConcurrentBag<Finding> findings)
        {
            List<Finding> filteredFindings = new List<Finding>();

            foreach (Finding f in findings)
            {
                try
                {
                    if ((f.FindingType.Equals(FindingType.URL_ENCODED.ToString())
                            && findings.Any(
                                e => (
                                    e.FrameNumber == f.FrameNumber
                                    && e.MatchedKeywords.Equals(f.MatchedKeywords) // TODO: check if matched keywords are equal as well
                                ) // URL encoding can be the same as plaintext, do not duplicate these
                            )
                        )
                        || filteredFindings.Any(
                                e => (
                                    e.FrameNumber == f.FrameNumber
                                    && e.FindingType.Equals(f.FindingType)
                                    && e.TimestampMillis.Equals(f.TimestampMillis)
                                ) // finding is already in filtered findings
                            )
                        )
                    {
                        continue;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex);
                    continue; // TODO: debug
                }

                if (f.IsHttps)
                {
                    nEncryptedFindings++;
                }

                filteredFindings.Add(f);
            }

            return filteredFindings;
        }

        private static int ParsePacketPayloads(TsharkWrapper pcapAnalyzer, MitmAnalyzer mitmAnalyzer, OtalyzerOptions otalyzerOptions)
        {
            // check whether pcap or mitm
            string extension = Path.GetExtension(otalyzerOptions.TrafficCaptureFile);

            Stopwatch swLoading = Stopwatch.StartNew();

            // analyze
            if (extension.ToLowerInvariant().Equals(".pcapng", StringComparison.OrdinalIgnoreCase)
                || extension.ToLowerInvariant().Equals(".pcap", StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine("[ ] Starting tshark-wrapper to load PCAPNG");

                if (otalyzerOptions.DecryptTls && !pcapAnalyzer.CheckKeylogFile())
                {
                    return (int)OtalyzerExit.INVALID_SSLKEYLOG_FILE;
                }

                if (pcapAnalyzer.RunTshark(out string tsharkResultsFile))
                {
                    Logger.Log($"Parsing {tsharkResultsFile}...");

                    if (!pcapAnalyzer.ParseTsharkResultsFile(tsharkResultsFile))
                    {
                        return (int)OtalyzerExit.TSHARK_PARSING_FAILED;
                    }
                }
                else
                {
                    Logger.LogNegative("Failed to run tshark");
                    return (int)OtalyzerExit.TSHARK_FAILED;
                }

                if (pcapAnalyzer.FoundPayloads.Count == 0)
                {
                    return (int)OtalyzerExit.NO_PAYLOADS_FOUND;
                }

                Logger.Log($"-> took {swLoading.ElapsedMilliseconds}ms...\n");
            }
            else if (extension.Equals(".mitm", StringComparison.OrdinalIgnoreCase))
            {
                IsMitmAnalysis = true;

                Console.WriteLine("[ ] Starting to load MITM");

                string jsonDumpFilename = otalyzerOptions.TrafficCaptureFile.Replace(extension, ".json");

                if (!File.Exists(jsonDumpFilename))
                {
                    if (!MitmproxyJsonDump.ConvertMitmFileToJson(otalyzerOptions.TrafficCaptureFile, out jsonDumpFilename))
                    {
                        Logger.LogNegative("Json dump failed, make sure you have mitmdump installed and in your $PATH... ");
                        return (int)OtalyzerExit.MITM_DUMP_FAILED;
                    }
                }

                using FileStream fs = new FileStream(jsonDumpFilename, FileMode.Open, FileAccess.Read);
                mitmAnalyzer.LoadStream(fs);
                mitmAnalyzer.ReadStream();

                swLoading.Stop();
                Logger.Log($"Loading MITM took {swLoading.ElapsedMilliseconds}ms...");

                if (mitmAnalyzer.MitmBlocks.Count == 0)
                {
                    return (int)OtalyzerExit.NO_PAYLOADS_FOUND;
                }
            }
            else
            {
                Logger.LogNegative("Packet file extension must be either .pcap[ng] or .mitm. Aborting.");
                return (int)OtalyzerExit.WRONG_EXTENSION;
            }

            return (int)OtalyzerExit.SUCCESS;
        }

        private static long PostProcess(List<Finding> findings, AnalyzationManager analyzationManager, Dictionary<string, Dictionary<string, int>> severityLevels)
        {
            return Utils.ExecutionTimeMs(() => analyzationManager.PostProcess(findings, severityLevels, IsMitmAnalysis));
        }
    }
}