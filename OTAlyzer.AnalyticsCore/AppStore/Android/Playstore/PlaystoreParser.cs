using Newtonsoft.Json;
using OTAlyzer.Common;
using System;
using System.Net;
using System.Text.RegularExpressions;

namespace OTAlyzer.AnalyticsCore.AppStore.Android.Playstore
{
    public class PlaystoreParser
    {
        public PlaystoreParser(string playstoreUrl)
        {
            PlaystoreUrl = playstoreUrl;
            PackageName = ParsePackageName();

            using WebClient webClient = new WebClient();
            PageContent = webClient.DownloadString(playstoreUrl);
        }

        public string PackageName { get; set; }

        public PlaystoreEntry PlaystoreEntry { get; private set; }

        public string PlaystoreUrl { get; }

        private string PageContent { get; }

        public bool TryParse(out PlaystoreEntry playstoreEntry)
        {
            try
            {
                dynamic appInfoJson = ReadAppInfoJson();

                PlaystoreEntry = new PlaystoreEntry()
                {
                    Url = PlaystoreUrl,
                    Name = (string)appInfoJson.name,
                    Developer = (string)appInfoJson.author.name,
                    DeveloperUrl = (string)appInfoJson.author.url,
                    Base64Image = ImageUtils.DownloadImageAsBase64((string)appInfoJson.image, "image/webp"),
                    Rating = Math.Round((double)appInfoJson.aggregateRating.ratingValue, 1),
                    TotalRatings = (int)appInfoJson.aggregateRating.ratingCount,
                    Usk = (string)appInfoJson.contentRating,
                    Price = (double)appInfoJson.offers[0].price,
                    Currency = (string)appInfoJson.offers[0].priceCurrency,
                    LastUpdate = ParseLastUpdateDate(),
                    LastVersion = ParseLastVersion(),
                    MinimalOsVersion = ParseMinimalAndroidVersion()
                };

                playstoreEntry = PlaystoreEntry;
            }
            catch
            {
                playstoreEntry = null;
                return false;
            }

            return true;
        }

        private string ParseAdditionalInfoField(string fieldname)
        {
            return PageContent.Split($"{fieldname}</div>")[1].Split("</span></div></span></div>")[0].Split(">")[3];
        }

        private string ParseLastUpdateDate()
        {
            return ParseAdditionalInfoField("Aktualisiert");
        }

        private string ParseLastVersion()
        {
            return ParseAdditionalInfoField("Aktuelle Version");
        }

        private string ParseMinimalAndroidVersion()
        {
            return ParseAdditionalInfoField("Erforderliche Android-Version");
        }

        private string ParsePackageName()
        {
            try
            {
                string pkgName = PlaystoreUrl.Split("id=")[1];
                if (pkgName.Contains("&"))
                {
                    pkgName = pkgName.Split("&")[0];
                }

                return pkgName;
            }
            catch
            {
                throw new ArgumentException("Url provided is not a valid Playstore Url...");
            }
        }

        private dynamic ReadAppInfoJson()
        {
            const string JSONSPLITFIRSTPART = "{\"@context\":\"https://schema.org\",\"@type\":\"SoftwareApplication\",";
            const string JSONSPLITLASTPART = "}]}";

            string json = PageContent.Split(JSONSPLITFIRSTPART)[1];
            json = json.Split(JSONSPLITLASTPART)[0];
            json = Regex.Unescape(json);
            json = JSONSPLITFIRSTPART + json + JSONSPLITLASTPART;

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