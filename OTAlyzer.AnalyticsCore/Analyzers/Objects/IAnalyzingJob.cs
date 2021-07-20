using OTAlyzer.AnalyticsCore.Analyzers.Searchers;

namespace OTAlyzer.AnalyticsCore.Analyzers.Objects
{
    public interface IAnalyzingJob
    {
        public delegate void JobFinished();

        public void Finish();
    }
}