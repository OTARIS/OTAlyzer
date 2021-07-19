using System.IO;

namespace OTAlyzer.AnalyticsCore.Traffic
{
    public interface IAnalyzer
    {
        void Analyze();

        void LoadStream(Stream stream);

        void ReadStream();
    }
}