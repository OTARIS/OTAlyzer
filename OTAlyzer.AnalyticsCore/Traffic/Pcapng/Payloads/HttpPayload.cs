using OTAlyzer.AnalyticsCore.Analyzers.Objects.Enums;
using OTAlyzer.AnalyticsCore.Traffic.Pcapng.Packets;
using OTAlyzer.AnalyticsCore.Traffic.Pcapng.Payloads.Enums;
using System;
using System.Collections.Generic;
using System.Text;

namespace OTAlyzer.AnalyticsCore.Traffic.Pcapng.Payloads
{
    public class HttpPayload : IPcapngPayload
    {
        public string Content { get; private set; }

        public HttpMethod HttpMethod { get; private set; }

        public Dictionary<string, string> HttpHeaders { get; private set; }

        public int Length => Content.Length;

        public byte[] Payload { get; private set; }

        public TcpPacket TcpPacket { get; private set; }

        public string Version { get; private set; }

        public bool IsHttps { get; private set; }

        public EncryptionType EncryptionType { get; private set; }

        public static HttpPayload FromBytes(byte[] input, TcpPacket linkedTcpPacket = null, Encoding encoding = null)
        {
            if (input.Length == 0)
            {
                return null;
            }

            return FromText(encoding.GetString(input), linkedTcpPacket /*, encoding */);
        }

        public static HttpPayload FromText(string payloadString, TcpPacket linkedTcpPacket = null, Dictionary<string, string> HttpHeaders = null, bool IsHttps = false, string TlsCipher = null, Encoding encoding = null)
        {
            if (payloadString.Length == 0)
            {
                return null;
            }

            // default to ascii
            if (encoding == null)
            {
                encoding = Encoding.ASCII;
            }

            // default to GET - TODO: http.request.method
            HttpMethod method = HttpMethod.GET;
            if (Enum.TryParse(payloadString.Split(" ")[0], out HttpMethod _method))
            {
                method = _method;
            }

            string version = string.Empty; // TODO: get http version
            string content = payloadString;

            EncryptionType encryptionType = EncryptionType.NONE;
            // parse wireshark value to enum
            switch (TlsCipher)
            {
                case "SSLv2":
                    encryptionType = EncryptionType.SSL2_0;
                    break;
                case "SSLv3":
                    encryptionType = EncryptionType.SSL3_0;
                    break;
                case "TLSv1.0":
                    encryptionType = EncryptionType.TLS1_0;
                    break;
                case "TLSv1.1":
                    encryptionType = EncryptionType.TLS1_1;
                    break;
                case "TLSv1.2":
                    encryptionType = EncryptionType.TLS1_2;
                    break;
                case "TLSv1.3":
                    encryptionType = EncryptionType.TLS1_3;
                    break;
            }

            return new HttpPayload
            {
                Payload = encoding.GetBytes(payloadString),
                Version = version,
                HttpMethod = method,
                Content = content,
                TcpPacket = linkedTcpPacket,
                HttpHeaders = HttpHeaders,
                IsHttps = IsHttps,
                EncryptionType = encryptionType
            };
        }

        public static bool IsHttpPayload(byte[] payload)
        {
            try
            {
                string content = Encoding.ASCII.GetString(payload);

                // Try to parse the HTTP Protocol (example: GET/HTTP/1.1...)
                if (content.Split("\r\n")[0].Trim().Contains("HTTP", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex); // ignored for now
            }

            return false;
        }

        public string GetString()
        {
            return Encoding.ASCII.GetString(Payload);
        }
    }
}