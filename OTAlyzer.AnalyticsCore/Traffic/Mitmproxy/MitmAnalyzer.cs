using Newtonsoft.Json;
using OTAlyzer.AnalyticsCore.Traffic.Mitmproxy.Blocks;
using System.Collections.Generic;
using System.IO;

namespace OTAlyzer.AnalyticsCore.Traffic.Mitmproxy
{
    public class MitmAnalyzer : IAnalyzer
    {
        public MitmAnalyzer(int maxBlockSize = int.MaxValue)
        {
            MaxBlockSize = maxBlockSize;
            MitmBlocks = new List<MitmBlock>();
        }

        public List<MitmBlock> MitmBlocks { get; }

        private int MaxBlockSize { get; }

        private Stream MitmFileStream { get; set; }

        public void Analyze()
        {
            // unused, analysis happens while reading
        }

        public void LoadStream(Stream mitmStream)
        {
            MitmFileStream = mitmStream;
        }

        public void ReadStream()
        {
            using StreamReader reader = new StreamReader(MitmFileStream);

            while (reader.BaseStream.Position < reader.BaseStream.Length)
            {
                string line = reader.ReadLine();

                if (line.Length < MaxBlockSize)
                {
                    MitmBlocks.Add(JsonConvert.DeserializeObject<MitmBlock>(line));
                }
            }
        }
    }
}