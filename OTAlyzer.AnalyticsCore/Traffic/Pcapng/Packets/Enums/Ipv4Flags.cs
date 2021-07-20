using System;

namespace OTAlyzer.AnalyticsCore.Traffic.Pcapng.Packets.Enums
{
    [Flags]
    public enum Ipv4Flags
    {
        None = 0,
        MORE_FRAGMENTS = 1 << 5,
        DO_NOT_FRAGMENT = 1 << 6,
        RESERVED = 1 << 7
    }
}