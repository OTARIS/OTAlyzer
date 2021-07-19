using OTAlyzer.AnalyticsCore.Analyzers.Searchers;

namespace OTAlyzer.AnalyticsCore.Analyzers.Objects
{
    public class AnalyzingJob
    {
        public AnalyzingJob(int payloadId, IKeywordSearcher keywordSearcher, JobFinished jobFinishedCallback)
        {
            PayloadId = payloadId;
            KeywordSearcher = keywordSearcher;
            OnJobFinished += jobFinishedCallback;
        }

        public delegate void JobFinished();

        public event JobFinished OnJobFinished;

        public IKeywordSearcher KeywordSearcher { get; }

        public int PayloadId { get; }

        public void Finish()
        {
            OnJobFinished?.Invoke();
        }
    }
}