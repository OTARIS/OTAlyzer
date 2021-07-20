namespace OTAlyzer.AnalyticsCore.Traffic.Misc
{
    public class AnalyzeableString : IAnalyzeable
    {
        public AnalyzeableString(string s)
        {
            S = s;
            Length = S.Length;
        }

        public int Length { get; }

        private string S { get; }

        public string GetString()
        {
            return S;
        }
    }
}