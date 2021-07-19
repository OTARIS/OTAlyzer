using OTAlyzer.AnalyticsCore.Location.Iplocation.Objects;
using System.Net;

namespace OTAlyzer.AnalyticsCore.Location.Iplocation
{
    public interface IIplocationProvider
    {
        IpLocation Get(IPAddress ip);
    }
}