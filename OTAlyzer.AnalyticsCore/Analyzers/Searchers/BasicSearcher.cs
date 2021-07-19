using OTAlyzer.AnalyticsCore.Analyzers.Objects.Enums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace OTAlyzer.AnalyticsCore.Analyzers.Searchers
{
    public abstract class BasicSearcher : IKeywordSearcher
    {
        protected BasicSearcher(StringComparison stringComparison = StringComparison.OrdinalIgnoreCase, Encoding encoding = null)
        {
            StringComparison = stringComparison;
            Encoding = encoding ?? Encoding.ASCII;
        }

        public abstract FindingType FindingType { get; }

        public Dictionary<string, List<string>> KeywordList { get; protected set; }

        protected Encoding Encoding { get; }

        protected StringComparison StringComparison { get; }

        public virtual Dictionary<string, List<string>> Search(ref string input, bool allowDuplicates)
        {
            Dictionary<string, List<string>> findings = new Dictionary<string, List<string>>();

            foreach (KeyValuePair<string, List<string>> list in KeywordList)
            {
                foreach (string keyword in list.Value)
                {
                    if (keyword.Length > 0)
                    {
                        if (keyword.StartsWith("$regex$"))
                        {
                            Regex regex = new Regex(keyword.Split("$regex$")[1]);
                            MatchCollection matches = regex.Matches(input);

                            if (matches.Any())
                            {
                                if (!findings.ContainsKey(list.Key))
                                {
                                    findings.Add(list.Key, new List<string>());
                                }

                                foreach (Match m in matches)
                                {
                                    findings[list.Key].Add(GetMatchContext(m.Value, input));
                                }
                            }
                        }
                        else
                        {
                            if (input.Contains(keyword, StringComparison))
                            {
                                if (!findings.ContainsKey(list.Key))
                                {
                                    findings.Add(list.Key, new List<string>());
                                }

                                findings[list.Key].Add(GetMatchContext(keyword, input));
                            }
                        }
                    }
                }
            }

            if (!allowDuplicates)
            {
                Dictionary<string, List<string>> findingsOld = new Dictionary<string, List<string>>(findings);

                foreach (string key in findingsOld.Keys)
                {
                    findings[key] = findings[key].Distinct().ToList();
                }
            }

            return findings;
        }

        private string GetMatchContext(string match, string input)
        {
            // Returns the match including n chars before and after it, where n is padding
            int padding = 100;
            input = new string(' ', padding) + input.Replace("\\", "") + new string(' ', padding * 2);

            int ctxStartIndex = input.IndexOf(match, StringComparison) - padding;
            int ctxEndIndex = padding * 2 + match.Length;
            string m;
            try
            {
                m = input.Substring(ctxStartIndex, ctxEndIndex);
                return $"[ ..{m}.. ]";
            }
            catch (ArgumentOutOfRangeException)
            {
                m = match;
            }
            return m;
        }
    }
}