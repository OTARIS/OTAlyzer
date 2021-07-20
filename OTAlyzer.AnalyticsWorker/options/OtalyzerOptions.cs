using System.Collections.Generic;

namespace OTAlyzer.AnalyticsWorker.Options
{
    public class OtalyzerOptions
    {
        public string AnalysisName { get; set; }

        public List<string> BlacklistFiles { get; set; }

        public bool InCiPipeline { get; set; }

        public string KeywordListFile { get; set; }

        public string OutputFile { get; set; }

        public string SeverityLevelFile { get; set; }

        public string Sslkeylogfile { get; set; }

        public int Threshold { get; set; }

        public string TrafficCaptureFile { get; set; }

        public bool DecryptTls { get; set; } = false;
    }
}