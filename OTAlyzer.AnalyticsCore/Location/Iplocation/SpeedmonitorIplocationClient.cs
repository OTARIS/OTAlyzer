using Newtonsoft.Json;
using OTAlyzer.AnalyticsCore.Location.Iplocation.Objects;
using System;
using System.Collections.Concurrent;
using System.Net;

namespace OTAlyzer.AnalyticsCore.Location.Iplocation
{
    public class SpeedmonitorIplocationClient : IIplocationProvider
    {
        private static ConcurrentDictionary<string, IpLocation> IpLocationCache { get; } = new ConcurrentDictionary<string, IpLocation>();

        public IpLocation Get(IPAddress ip)
        {
            if (IpLocationCache.ContainsKey(ip.ToString()))
            {
                return IpLocationCache[ip.ToString()];
            }

            using WebClient webClient = new WebClient();
            string url = $"https://loadbalancer0.speedmonitor.net/api/iplocation?ip={ip.MapToIPv4()}";

            try
            {
                string json = webClient.DownloadString(url);

                IpLocation iplocation = JsonConvert.DeserializeObject<IpLocation>(json);
                IpLocationCache.TryAdd(ip.ToString(), iplocation);

                return iplocation;
            }
            catch (Exception)
            {
                return null;
            }
        }
    }
}