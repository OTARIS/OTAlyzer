using Newtonsoft.Json;
using OTAlyzer.Common;
using System;
using System.Net;

namespace OTAlyzer.AnalyticsCore.AppStore.Ios.Appstore
{
    public class AppstoreParser
    {
        public AppstoreParser(string appstoreUrl)
        {
            AppstoreUrl = appstoreUrl;

            using WebClient webClient = new WebClient();
            PageContent = webClient.DownloadString(appstoreUrl);
        }

        public AppstoreEntry AppstoreEntry { get; private set; }

        public string AppstoreUrl { get; }

        private string PageContent { get; }

        public bool TryParse(out AppstoreEntry appstoreEntry)
        {
            try
            {
                dynamic appInfoJson = ReadAppInfoJson();

                AppstoreEntry = new AppstoreEntry()
                {
                    Url = AppstoreUrl,
                    Name = (string)appInfoJson.name,
                    Developer = (string)appInfoJson.author.name,
                    DeveloperUrl = (string)appInfoJson.author.url,
                    Base64Image = ImageUtils.DownloadImageAsBase64(ParseImage(), ParseImageType()),
                    Rating = Math.Round((double)appInfoJson.aggregateRating.ratingValue, 1),
                    TotalRatings = (int)appInfoJson.aggregateRating.reviewCount,
                    Price = (double)appInfoJson.offers.price,
                    Currency = (string)appInfoJson.offers.priceCurrency,
                    MinimalOsVersion = (string)appInfoJson.operatingSystem,
                    LastVersion = ParseLastVersion(),
                    LastUpdate = ParseLastUpdate(),
                    Usk = ParseUsk()
                };

                appstoreEntry = AppstoreEntry;
            }
            catch (Exception e)
            {
                appstoreEntry = null;
                return false;
            }

            return true;
        }

        private string ParseImage()
        {
            return ParseMetaProperty("og:image");
        }

        private string ParseImageType()
        {
            return ParseMetaProperty("og:image:type");
        }

        private string ParseLastUpdate()
        {
            return PageContent.Split("<time data-test-we-datetime")[1].Split(">")[1].Split("<")[0];
        }

        private string ParseLastVersion()
        {
            return PageContent.Split("whats-new__latest__version\">Version ")[1].Split("<")[0];
        }

        private string ParseMetaProperty(string name)
        {
            return PageContent.Split($"<meta property=\"{name}\" content=\"")[1].Split("\"")[0];
        }

        private string ParseUsk()
        {
            try
            {
                return PageContent.Split("large-6\">Freigabe ")[1].Split("+")[0];
            }
            catch
            {
                return "unknown";
            }
        }

        private dynamic ReadAppInfoJson()
        {
            const string JSONSPLITFIRSTPART = "{\"@context\":\"http://schema.org\",\"@type\":\"SoftwareApplication\",";
            const string JSONSPLITLASTPART = "}}";

            string json = PageContent.Split(JSONSPLITFIRSTPART)[1];
            json = json.Split(JSONSPLITLASTPART)[0];
            json = $"{JSONSPLITFIRSTPART}{json}{JSONSPLITLASTPART}";

            dynamic dyn;
            try
            {
                dyn = JsonConvert.DeserializeObject(json);
            }
            catch
            {
                dyn = null;
            }

            return dyn;
        }
    }
}