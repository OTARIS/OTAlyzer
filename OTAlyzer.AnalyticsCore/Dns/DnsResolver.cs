using System.Collections.Concurrent;
using System.Net;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
namespace OTAlyzer.AnalyticsCore.Dns
{
    public class DnsResolver
    {
        public DnsResolver()
        {
            IpCache = new ConcurrentDictionary<string, IPAddress>();
        }

        private ConcurrentDictionary<string, IPAddress> IpCache { get; }

        public IPAddress Get(string url, int timeout = 5)
        {
            try
            {
                if (IpCache.ContainsKey(url))
                {
                    return IpCache[url];
                }
                else
                {
                    Task<IPHostEntry> task = new Task<IPHostEntry>(() =>
                    {
                        try { return System.Net.Dns.GetHostEntry(url); }
                        catch { return null; }
                    });
                    task.Start();

                    if (task.Wait(timeout))
                    {
                        // task completed within the timeout
                        return task.GetAwaiter().GetResult().AddressList[0];
                    }
                }
            }
            catch
            {
                /* ignored */
            }

            return null;
        }
    }
}