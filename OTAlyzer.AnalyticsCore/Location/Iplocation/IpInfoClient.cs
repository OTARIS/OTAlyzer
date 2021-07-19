using Newtonsoft.Json;
using OTAlyzer.AnalyticsCore.Location.Iplocation.Objects;
using System.Collections.Generic;
using System.Net;

namespace OTAlyzer.AnalyticsCore.Location.Iplocation
{
    public class IpInfoClient : IIplocationProvider
    {
        private static Dictionary<string, IpLocation> IpLocationCache { get; } = new Dictionary<string, IpLocation>();

        public IpLocation Get(IPAddress ip)
        {
            if (IpLocationCache.ContainsKey(ip.ToString()))
            {
                return IpLocationCache[ip.ToString()];
            }

            using WebClient webClient = new WebClient();
            try
            {
                string json = webClient.DownloadString($"https://ipinfo.io/{ip}/json/");

                dynamic result = JsonConvert.DeserializeObject<IpLocation>(json);
                IpLocation iplocation = new IpLocation()
                {
                    Ip = result.ip,
                    City = result.city,
                    RegionName = result.region,
                    CountryName = result.country,
                    Latitude = double.Parse(((string)result.country).Split(",")[0]),
                    Longitude = double.Parse(((string)result.country).Split(",")[1])
                };
                IpLocationCache.Add(ip.ToString(), iplocation);

                return iplocation;
            }
            catch
            {
                return null;
            }
        }
    }
}