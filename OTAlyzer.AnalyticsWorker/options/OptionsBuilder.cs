using OTAlyzer.Common;
using System;
using System.IO;
using System.Linq;

namespace OTAlyzer.AnalyticsWorker.Options
{
    public static class OptionsBuilder
    {
        public static bool TryParseCommandLineArguments(string[] args, out OtalyzerOptions options)
        {
            options = new OtalyzerOptions();

            if (args.Length == 0)
            {
                Program.DisplayBanner();
                Program.DisplayUsage();

                return false;
            }

            for (int i = 0; i < args.Length; i++)
            {
                try
                {
                    if (args[i] == "-k" || args[i] == "--keyword-file")
                    {
                        options.KeywordListFile = CheckFileExists(args[i + 1]) ? args[i + 1] : null;
                    }
                    else if (args[i] == "-s" || args[i] == "--severity-level-file")
                    {
                        options.SeverityLevelFile = CheckFileExists(args[i + 1]) ? args[i + 1] : null;
                    }
                    else if (args[i] == "-p" || args[i] == "--pcap-file")
                    {
                        options.TrafficCaptureFile = CheckFileExists(args[i + 1]) ? args[i + 1] : null;
                    }
                    else if (args[i] == "--tls")
                    {
                        if (!CheckFileExists(args[i + 1]))
                        {
                            return false;
                        }
                        else
                        {
                            options.Sslkeylogfile = args[i + 1];
                            options.DecryptTls = true;
                        }
                    }
                    else if (args[i] == "--filename")
                    {
                        if (args[i + 1].StartsWith('-')) { Logger.LogAlert($"You need to supply an argument to {args[i]} and not a parameter like {args[i + 1]}."); throw new ArgumentException(); }
                        options.OutputFile = $"{args[i + 1]}.json";
                    }
                    else if (args[i] == "--severity-threshold")
                    {
                        if (args[i + 1].StartsWith('-')) { Logger.LogAlert($"You need to supply an argument to {args[i]} and not a parameter like {args[i + 1]}."); throw new ArgumentException(); }
                        options.InCiPipeline = true;
                        options.Threshold = int.Parse(args[i + 1]);
                    }
                    else if (args[i] == "--blacklists")
                    {
                        if (args[i + 1].StartsWith('-')) { Logger.LogAlert($"You need to supply an argument to {args[i]} and not a parameter like {args[i + 1]}."); throw new ArgumentException(); }
                        options.BlacklistFiles = args[i + 1].Split(',').ToList();
                    }
                    else if (args[i] == "-h" || args[i] == "--help" || args[i] == "--usage")
                    {
                        Program.DisplayBanner();
                        Program.DisplayUsage();

                        return false;
                    }
                }
                catch (IndexOutOfRangeException)
                {
                    Logger.LogAlert($"You need to supply an argument to {args[i]}.");
                    Logger.Log("See --help or -h for help.");

                    return false;
                }
            }

            // if mandatory parameters are missing, display the usage and exit
            if (!(args.Contains("-k") || args.Contains("--keyword-file")) ||
                !(args.Contains("-p") || args.Contains("--pcap-file")) ||
                !(args.Contains("-s") || args.Contains("--severity-level-file")) ||
                !(args.Contains("--filename")))
            {
                Logger.Log("Keyword & severity file, network-file and filename are mandatory. See --help or -h for help.");

                return false;
            }

            // return false if wrong filepaths
            if (options.KeywordListFile == null || options.TrafficCaptureFile == null)
            {
                Logger.LogAlert("Exiting.\n");
                Logger.Log("See --help or -h for help.");

                return false;
            }

            return true;
        }

        private static bool CheckFileExists(string FilePath)
        {
            if (!File.Exists(FilePath))
            {
                Logger.LogAlert($"Supplied path >{FilePath}< is not a valid filepath.");
                return false;
            }

            return true;
        }
    }
}