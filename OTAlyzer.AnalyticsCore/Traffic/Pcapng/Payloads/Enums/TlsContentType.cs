namespace OTAlyzer.AnalyticsCore.Traffic.Pcapng.Payloads.Enums
{
    // see https://tools.ietf.org/html/rfc5246#appendix-A.1
    public enum TlsContentType : byte
    {
        CHANGE_CIPHER_SPEC = 20,
        ALERT = 21,
        HANDSHAKE = 22,
        APPLICATION_DATA = 23
    }
}