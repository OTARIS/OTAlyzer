using OTAlyzer.AnalyticsCore.Traffic.Pcapng.Packets;
using System;

namespace OTAlyzer.AnalyticsCore.Traffic.Pcapng.Payloads
{
    public static class PayloadIdentifier
    {
        public static bool TryIdentifyTcpPacket(TcpPacket tcpPacket, out IPcapngPayload payload)
        {
            try
            {
                //// disabled for now, will be processed in the TlsAnalyzer if
                //// (TlsPayload.IsTlsPayload(tcpPacket.Payload)) { payload =
                //// TlsPayload.FromBytes(tcpPacket.Payload, tcpPacket); return true; }
                if (HttpPayload.IsHttpPayload(tcpPacket.Payload))
                {
                    payload = HttpPayload.FromBytes(tcpPacket.Payload, tcpPacket);
                    return true;
                    ;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex); // ignored for now
            }

            // default
            payload = TcpPayload.FromBytes(tcpPacket.Payload, tcpPacket);

            return false;
        }
    }
}