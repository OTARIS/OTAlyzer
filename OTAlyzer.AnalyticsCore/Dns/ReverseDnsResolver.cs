using System.Collections.Concurrent;
using System.Net;
using System.Threading.Tasks;

namespace OTAlyzer.AnalyticsCore.Dns
{
    public class ReverseDnsResolver
    {
        public ReverseDnsResolver()
        {
            HostnameCache = new ConcurrentDictionary<IPAddress, string>();
        }

        private ConcurrentDictionary<IPAddress, string> HostnameCache { get; }

        public string Get(IPAddress ip, int timeout = 5)
        {
            try
            {
                if (HostnameCache.ContainsKey(ip))
                {
                    return HostnameCache[ip];
                }
                else
                {
                    Task<IPHostEntry> task = new Task<IPHostEntry>(() =>
                    {
                        try { return System.Net.Dns.GetHostEntry(ip); }
                        catch { return null; }
                    });
                    task.Start();

                    if (task.Wait(timeout))
                    {
                        // task completed within the timeout
                        return task.GetAwaiter().GetResult().HostName;
                    }
                }
            }
            catch
            {
                /* ignored */
            }

            return string.Empty;
        }
    }
}