using Newtonsoft.Json.Linq;
using OTAlyzer.AnalyticsCore.Analyzers.Objects;
using OTAlyzer.AnalyticsCore.Analyzers.Objects.Enums;
using OTAlyzer.AnalyticsCore.Traffic.Mitmproxy.Blocks;
using OTAlyzer.AnalyticsCore.Traffic.Pcapng.Payloads;
using OTAlyzer.Common;
using System;
using System.Collections.Generic;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace OTAlyzer.AnalyticsCore.Analyzers
{
    public static class FindingBuilder
    {
        private static long FindingID = 0;

        public static Finding Build(object payload, FindingType findingType, Dictionary<string, List<string>> keywords, Encoding encoding = null)
        {
            encoding ??= Encoding.ASCII;

            if (payload.GetType() == typeof(HttpPayload))
            {
                FindingID++;
                return BuildFromHttpPayload((HttpPayload)payload, findingType, keywords, encoding);
            }
            if (payload.GetType() == typeof(MqttPayload))
            {
                FindingID++;
                return BuildFromMqttPayload((MqttPayload)payload, findingType, keywords, encoding);
            }
            if (payload.GetType() == typeof(MitmBlock))
            {
                FindingID++;
                return BuildFromMitmBlock((MitmBlock)payload, findingType, keywords, encoding);
            }
            return null;
        }

        private static Finding BuildFromMqttPayload(MqttPayload mqttPayload, FindingType findingType, Dictionary<string, List<string>> keywords, Encoding encoding)
        {
            string srcIp = new IPAddress(mqttPayload.TcpPacket.Ipv4Packet.IpAddressSource).ToString();
            string dstIp = new IPAddress(mqttPayload.TcpPacket.Ipv4Packet.IpAddressDestination).ToString();

            return new Finding(srcIp, dstIp, findingType, keywords, Convert.ToBase64String(mqttPayload.Payload), /*findingType != FindingType.PLAIN_TEXT ? ProcessRawKeywords(keywords, findingType, encoding) : */ null)
            {
                FrameNumber = mqttPayload.TcpPacket.Ipv4Packet.EthernetPacket.FrameNumber,
                SourceIp = srcIp,
                DestinationIp = dstIp,
                SourcePort = mqttPayload.TcpPacket.SourcePort,
                DestinationPort = mqttPayload.TcpPacket.DestinationPort,
                SourceMac = mqttPayload.TcpPacket.Ipv4Packet.EthernetPacket.MacAddressSource,
                DestinationMac = mqttPayload.TcpPacket.Ipv4Packet.EthernetPacket.MacAddressDestination,
                IsHttps = false, // TODO: mqtt istls 
                EncryptionType = mqttPayload.EncryptionType.ToString(),
                TimestampMillis = mqttPayload.TcpPacket.Ipv4Packet.EthernetPacket.GetTimestampInMilliseconds(),
            };
        }

        public static Finding BuildFromHttpPayload(HttpPayload httpPayload, FindingType findingType, Dictionary<string, List<string>> keywords, Encoding encoding = null)
        {
            encoding ??= Encoding.ASCII;

            if (TryParseHttpRequest(httpPayload, encoding, out string url, out string _, out Dictionary<string, string> httpHeaders))
            {
                string srcIp = new IPAddress(httpPayload.TcpPacket.Ipv4Packet.IpAddressSource).ToString();
                string dstIp = new IPAddress(httpPayload.TcpPacket.Ipv4Packet.IpAddressDestination).ToString();

                string sourceUrl = srcIp;
                string destinationUrl = dstIp + url;

                if (httpHeaders.ContainsKey("Host"))
                {
                    destinationUrl = $"{httpHeaders["Host"]}{url}";
                }

                // string payload = httpPayload.Payload.Length < MAXPAYLOADLENGTH ?
                // encoding.GetString(httpPayload.Payload).Trim() : "Payload is too large to display...";

                // TODO: get fulL dest URL with get params and full path

                return new Finding(sourceUrl, destinationUrl, findingType, keywords, Convert.ToBase64String(httpPayload.Payload), /*findingType != FindingType.PLAIN_TEXT ? ProcessRawKeywords(keywords, findingType, encoding) : */ null)
                {
                    FrameNumber = httpPayload.TcpPacket.Ipv4Packet.EthernetPacket.FrameNumber,
                    SourceIp = srcIp,
                    DestinationIp = dstIp,
                    SourcePort = httpPayload.TcpPacket.SourcePort,
                    DestinationPort = httpPayload.TcpPacket.DestinationPort,
                    SourceMac = httpPayload.TcpPacket.Ipv4Packet.EthernetPacket.MacAddressSource,
                    DestinationMac = httpPayload.TcpPacket.Ipv4Packet.EthernetPacket.MacAddressDestination,
                    IsHttps = httpPayload.IsHttps,
                    EncryptionType = httpPayload.EncryptionType.ToString(),
                    TimestampMillis = httpPayload.TcpPacket.Ipv4Packet.EthernetPacket.GetTimestampInMilliseconds(),
                    HttpHeaders = httpPayload.HttpHeaders,
                };
            }

            return null;
        }

        public static Finding BuildFromMitmBlock(MitmBlock mitmBlock, FindingType findingType, Dictionary<string, List<string>> keywords, Encoding encoding = null)
        {
            encoding ??= Encoding.ASCII;

            return (mitmBlock.Type.ToUpper()) switch
            {
                "HTTP" => HandleHttpBlock(mitmBlock, findingType, keywords, encoding),
                _ => null,
            };
        }

        private static Finding HandleHttpBlock(MitmBlock mitmblock, FindingType findingType, Dictionary<string, List<string>> keywords, Encoding encoding)
        {
            try
            {
                string srcIp = (string)mitmblock.ClientConnection["address"]["host"];
                ushort srcPort = (ushort)mitmblock.ClientConnection["address"]["port"];
                string dstIp = (string)mitmblock.ServerConnection["address"]["host"];
                ushort dstPort = (ushort)mitmblock.ServerConnection["address"]["port"];

                bool IsHttps = (bool)mitmblock.ClientConnection["tls_established"];

                EncryptionType encryptionType = IsHttps
                    ? ParseMitmTlsVersion((string)mitmblock.ClientConnection["tls_version"])
                    : EncryptionType.NONE;

                string sourceUrl = $"{srcIp}";
                string destinationUrl = TryBuildDestinationString(mitmblock, srcPort, dstIp, dstPort);

                string payload = HandleSpecificContentType(mitmblock.Request); // TODO: also parse response -> refactor findings into reponse paylaod, request payload
                // string payload = content.Length < MAXPAYLOADLENGTH ?
                // ProcessMitmPayload(content.Trim()) : "Payload is too large to display...";
 
                 // TODO : FulL Destionation URL with get params etc.

                return new Finding(sourceUrl, destinationUrl, findingType, keywords, Convert.ToBase64String(Encoding.UTF8.GetBytes(payload != null ? payload : "")), findingType != FindingType.PLAIN_TEXT ? ProcessRawKeywords(keywords, findingType, encoding) : null)
                {
                    FrameNumber = FindingID,
                    SourceIp = $"{srcIp}:{srcPort}",
                    DestinationIp = $"{dstIp}:{dstPort}",
                    SourcePort = srcPort,
                    DestinationPort = dstPort,
                    IsHttps = IsHttps,
                    EncryptionType = encryptionType.ToString(),
                    TimestampMillis = long.Parse((string)mitmblock.ClientConnection["timestamp_start"]),
                    HttpHeaders = mitmblock.Request["headers"].ToObject<Dictionary<string, string>>(),
                };
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex); // ignored for now
            }

            return null;
        }

        private static string HandleSpecificContentType(JObject input)
        {
            try
            {
                string contentType = string.Empty;

                if (((JObject)input["headers"]).TryGetValue("content-type", StringComparison.OrdinalIgnoreCase, out JToken contentTypeR))
                {
                    contentType = (string)contentTypeR;
                }

                contentType = contentType.Trim();

                string additionalParam = string.Empty;

                // this could look like this "text/html;charset=utf-8"
                try
                {
                    if (contentType.Contains(";"))
                    {
                        string[] parts = contentType.Split(";");
                        contentType = parts[0].Trim();
                        additionalParam = parts[1].Trim();
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex); // ignored for now
                }

                switch (contentType)
                {
                    case "application/x-www-form-urlencoded":
                        return HttpUtility.UrlDecode((string)input["content"]);
                }
            }
            catch (Exception ex)
            {
                return (string)input["content"];
            }


            return (string)input["content"];
        }

        private static EncryptionType ParseMitmTlsVersion(string tlsVersion)
        {
            if (Enum.TryParse(tlsVersion.Replace("v", string.Empty).Replace(".", "_").ToUpper(), out EncryptionType encryptionType))
            {
                return encryptionType;
            }
            else
            {
                return EncryptionType.NONE;
            }
        }

        private static string ProcessRawKeyword(string keyword, FindingType findingType, Encoding encoding)
        {
            return findingType switch
            {
                FindingType.BASE64_ENCODED => Convert.ToBase64String(encoding.GetBytes(keyword)),
                FindingType.MD5_HASHED => Utils.ByteArrayToString(MD5.Create().ComputeHash(encoding.GetBytes(keyword))),
                FindingType.SHA1_HASHED => Utils.ByteArrayToString(SHA1.Create().ComputeHash(encoding.GetBytes(keyword))),
                FindingType.SHA256_HASHED => Utils.ByteArrayToString(SHA256.Create().ComputeHash(encoding.GetBytes(keyword))),
                FindingType.SHA384_HASHED => Utils.ByteArrayToString(SHA384.Create().ComputeHash(encoding.GetBytes(keyword))),
                FindingType.SHA512_HASHED => Utils.ByteArrayToString(SHA512.Create().ComputeHash(encoding.GetBytes(keyword))),
                FindingType.NTLM_HASHED => Utils.ByteArrayToString(OTAlyzer.AnalyticsCore.Analyzers.Searchers.NTLMSearcher.NTHashAsBytes(keyword)),
                FindingType.URL_ENCODED => HttpUtility.UrlEncode(encoding.GetBytes(keyword)),
                FindingType.PLAIN_TEXT => keyword,
                _ => keyword,
            };
        }

        private static Dictionary<string, List<string>> ProcessRawKeywords(Dictionary<string, List<string>> keywords, FindingType findingType, Encoding encoding)
        {
            Dictionary<string, List<string>> rawKeywords = new Dictionary<string, List<string>>();

            foreach (KeyValuePair<string, List<string>> keyValuePair in keywords)
            {
                if (!rawKeywords.ContainsKey(keyValuePair.Key))
                {
                    rawKeywords.Add(keyValuePair.Key, new List<string>());
                }

                foreach (string s in keyValuePair.Value)
                {
                    rawKeywords[keyValuePair.Key].Add(ProcessRawKeyword(s, findingType, encoding));
                }
            }

            return rawKeywords;
        }

        private static string TryBuildDestinationString(MitmBlock mitmblock, int srcPort, string dstIp, int dstPort)
        {
            string destinationString = string.Empty;

            // try the sni field in ServerConnection this may fail due to missing sni name
            try
            {
                if (mitmblock.ServerConnection.TryGetValue("sni", out JToken sni))
                {
                    string sniString = sni.ToObject<string>();

                    if (!string.IsNullOrWhiteSpace(sniString))
                    {
                        //// add this to display full url {mitmblock.Request["path"]}
                        destinationString = $"{mitmblock.Request["scheme"]}://{sniString}:{dstPort}";
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex); // ignored for now
            }


            // try the Host header in request
            if (destinationString.Length == 0)
            {
                try
                {
                    //// add this to display full url {mitmblock.Request["path"]}
                    destinationString = $"{mitmblock.Request["scheme"]}://{mitmblock.Request["headers"]["Host"]}:{dstPort}{mitmblock.Request["path"]}";
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex); // ignored for now
                }

            }

            // use the fallback, ip address
            if (destinationString.Length == 0)
            {
                destinationString = $"{mitmblock.Request["scheme"]}://{dstIp}:{srcPort}{mitmblock.Request["path"]}";
            }

            return destinationString;
        }

        private static bool TryParseHttpRequest(HttpPayload httpPayload, Encoding encoding, out string url, out string httpContent, out Dictionary<string, string> httpHeaders)
        {
            url = null;
            httpContent = null;
            httpHeaders = null;

            try
            {
                // decode Http Content
                string rawHttpContent = encoding.GetString(httpPayload.Payload);

                // split Headers and Content
                string[] httpParts = rawHttpContent.Split("\r\n\r\n");

                string[] rawHttpHeaders = httpParts[0].Split("\r\n");
                try
                {
                    httpContent = httpParts[1];
                }
                catch (IndexOutOfRangeException)
                {
                    httpContent = httpParts[0];
                }
                string[] httpFirstRow = rawHttpHeaders[0].Split(" ");

                // TODO: parse http.request.uri.path
                url = string.Empty;

                // Do not get a wrong url when parsing http answers
                if (rawHttpHeaders[0] != "HTTP/1.1 200 OK")
                {
                    if (httpFirstRow.Length >= 3)
                    {
                        url = httpFirstRow[1];
                    }
                    else if (httpFirstRow.Length >= 2)
                    {
                        url = httpFirstRow[0];
                    }
                }

                httpHeaders = httpPayload.HttpHeaders;

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
                return false;
            }
        }
    }
}