using Microsoft.VisualBasic.FileIO;
using OTAlyzer.AnalyticsCore.Analyzers.Objects;
using OTAlyzer.AnalyticsCore.Traffic.Pcapng.Packets;
using OTAlyzer.AnalyticsCore.Traffic.Pcapng.Payloads;
using OTAlyzer.Common;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace OTAlyzer.AnalyticsCore.Analyzers
{
    public class TsharkWrapper
    {
        public static readonly Dictionary<string, int> TsharkFields = new Dictionary<string, int>()
        {
            { "frame.number",                0 },
            { "frame.time",                  1 },
            { "eth.src",                     2 },
            { "eth.dst",                     3 },
            { "ip.src",                      4 },
            { "ip.dst",                      5 },
            { "ip.hdr_len",                  6 },
            { "tcp.srcport",                 7 },
            { "tcp.dstport",                 8 },
            { "tcp.seq",                     9 },
            { "tcp.ack",                     10 },
            { "http.host",                   11 },
            { "http.authorization",          12 },
            { "http2.headers.authorization", 13 },
            { "http.set_cookie",             14 },
            { "http2.headers.set_cookie",    15 },
            { "http.user_agent",             16 },
            { "http2.headers.user_agent",    17 },
            { "http.referer",                18 },
            { "http2.headers.referer",       19 },
            { "http.cookie",                 20 },
            { "http2.headers.cookie",        21 },
            { "json.key",                    22 },
            { "json.value.string",           23 },
            { "json.value.number",           24 },
            { "urlencoded-form.key",         25 },
            { "urlencoded-form.value",       26 },
            { "image-gif.image.width",       27 },
            { "image-gif.image.height",      28 },
            { "_ws.col.Protocol",            29 },
            { "tls.record.version",          30 },
            { "text",                        31 },
            { "tls.segment.data",            32 },
            { "tls.record.length",           33 },
            { "mqtt.hdrflags",               34 },
            { "mqtt.msg",                    35 },
            { "mqtt.topic",                  36 },
            { "mqtt.passwd",                 37 },
            { "mqtt.username",               38 },
            { "mqtt.connack.reason_code",    39 },
            { "mqtt.clientid",               40 },
            { "mqtt.conflag.cleansess",      41 },
            { "mqtt.conack.flags.sp",        42 },
            { "sll.src.eth",                 43 },
            { "mqtt.protoname",              44 },
            { "mqtt.willmsg",                45 },
            { "mqtt.willtopic",              46 },
            { "mqtt.passwd_len",             47 },
            { "mqtt.ver",                    48 },
        };

        public TsharkWrapper(string pcapFile, bool useTls, string sslKeyLogFile)
        {
            TlsEnabled = useTls;
            SslKeyLogFile = sslKeyLogFile;
            PcapFile = pcapFile;
        }

        public List<IPcapngPayload> FoundPayloads { get; set; }

        private string PcapFile { get; }

        private string SslKeyLogFile { get; }

        private bool TlsEnabled { get; }

        public bool CheckKeylogFile()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                // grep if key for at least one tls exchange from
                // trafficCaptureFile exists in the SslKeyLogFile
                string args = $"-c \"grep -f <(tshark -r {PcapFile} -Y tls.handshake.type==1 -T fields -e tls.handshake.random) {SslKeyLogFile}\"";

                Process process = new Process();

                process.StartInfo.FileName = "bash";
                process.StartInfo.Arguments = args;
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.CreateNoWindow = true;
                process.StartInfo.RedirectStandardOutput = true;

                process.Start();
                process.BeginOutputReadLine();
                process.WaitForExit();

                return process.ExitCode == 0;
            }
            else
            {
                // TODO: implement the above using windows internals
                return File.ReadAllLines(SslKeyLogFile).Length > 0;
            }

            
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public string GetFieldOrDefault(string[] row, string fieldName, string defaultValue = "")
        {
            return TryGetField(row, fieldName, out string value) ? value : defaultValue;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public string GetFieldWithPrefixOrDefault(string[] row, string prefix, string fieldName, string defaultValue = "")
        {
            return TryGetField(row, fieldName, out string value) ? $"{prefix} {value}" : defaultValue;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public string GetTlsCipher(string tlsRecord)
        {
            if (tlsRecord.Contains("0x00000301"))
            {
                return "TLSv1.0";
            }
            if (tlsRecord.Contains("0x00000302"))
            {
                return "TLSv1.1";
            }
            if (tlsRecord.Contains("0x00000303"))
            {
                return "TLSv1.2";
            }
            if (tlsRecord.Contains("0x00000304"))
            {
                return "TLSv1.3";
            }
            return string.Empty;
        }

        public bool ParseTsharkResultsFile(string tsharkResultsFile)
        {
            if (!File.Exists(tsharkResultsFile))
            {
                return false;
            }

            FoundPayloads = ParsePacketsCsv(tsharkResultsFile);

            if (FoundPayloads.Count > 0)
            {
                Logger.LogPositive($"Found {FoundPayloads.Count} payloads");
            }
            else
            {
                Logger.LogNegative("No payloads found.");
            }

            return true;
        }

        public bool RunTshark(out string tsharkResultsFile)
        {
            tsharkResultsFile = string.Empty;

            // temp file to store the csv results
            string resultsFile = Path.GetTempFileName();

            string tsharkArgs = $"-r \"{PcapFile}\" ";

            // tshark needs additional args when processing tls
            if (TlsEnabled)
            {
                if (string.IsNullOrWhiteSpace(SslKeyLogFile) || !File.Exists(SslKeyLogFile))
                {
                    Logger.LogAlert("No SslKeyLogFile present to decrypt TLS. Aborting.");
                    return false;
                }

                tsharkArgs += "-o \"tls.debug_file:ssldebug.log\"" +
                        " -o \"tls.desegment_ssl_records:TRUE\"" +
                        " -o \"tls.desegment_ssl_application_data:TRUE\"" +
                        $" -o \"tls.keylog_file:{SslKeyLogFile}\"" + 
                        " -d \"tls.port==0-65535,http\""; 
            }

            tsharkArgs += " -o http.decompress_body:TRUE -E separator=/t -T fields " + BuildTsharkFieldsArgs();

            bool result = RunTsharkWithArgs(tsharkArgs, resultsFile);

            if (result)
            {
                tsharkResultsFile = resultsFile;
            }

            return result;
        }

        private static string BuildTsharkFieldsArgs()
        {
            StringBuilder sb = new StringBuilder();

            // append fields to arguments-string
            foreach (string field in TsharkFields.Keys)
            {
                sb.Append(" -e ").Append(field);
            }

            return sb.ToString();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public bool TryGetField(string[] row, string fieldName, out string value)
        {
            if (TsharkFields.ContainsKey(fieldName))
            {
                value = row[TsharkFields[fieldName]];

                if (!string.IsNullOrWhiteSpace(value))
                {
                    return true;
                }
            }

            value = string.Empty;
            return false;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public bool TryGetField<T>(string[] row, string fieldName, out T value) where T : unmanaged
        {
            if (TryGetField(row, fieldName, out string textValue))
            {
                try
                {
                    value = (T)Convert.ChangeType(textValue, typeof(T));
                    return true;
                }
                catch
                {
                    Logger.LogAlert($"Failed to ChangeType of \"{textValue}\" to {nameof(T)}");
                }
            }

            value = default;
            return false;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public bool TryGetFields(string[] row, out string value, params string[] fieldNames)
        {
            foreach (string fieldName in fieldNames)
            {
                if (TryGetField(row, fieldName, out value))
                {
                    return true;
                }
            }

            value = string.Empty;
            return false;
        }

        private IPcapngPayload BuildPayloadFromCsvRow(string[] row, string payload, bool isHttps)
        {
            // parse Layer 2 (ETHERNET)
            EthernetPacket LinkedEthernetPacket = ParseEthernet(row);

            // parse Layer 3 (IP)
            if (TryGetField(row, "ip.hdr_len", out int ipHeaderLen)
                && TryGetField(row, "ip.src", out string ipSrc)
                && TryGetField(row, "ip.dst", out string ipDst)
                && Ipv4Packet.FromText(ipSrc, ipDst, ipHeaderLen, out Ipv4Packet LinkedIpv4Packet, LinkedEthernetPacket))
            {
                // parse Layer 4 (TCP) TODO: handle UDP 
                if (TryGetField(row, "tcp.srcport", out ushort tcpSrcPort)
                    && TryGetField(row, "tcp.dstport", out ushort tcpDstPort)
                    && TryGetField(row, "tcp.seq", out uint tcpSeq)
                    && TryGetField(row, "tcp.ack", out uint tcpAck)
                    && TcpPacket.FromText(tcpSrcPort, tcpDstPort, tcpSeq, tcpAck, out TcpPacket LinkedTcpPacket, LinkedIpv4Packet))
                {
                    // layer 5-7 (HTTP)
                    if (TryGetField(row, "http.host", out string httpHost))
                    {
                        Dictionary<string, string> HttpHeaders = new Dictionary<string, string>();

                        HttpHeaders["Host"] = httpHost;

                        if (TryGetFields(row, out string httpAuth, "http.authorization",
                            "http2.headers.authorization"))
                        {
                            HttpHeaders["Authorization"] = httpAuth;
                        }

                        if (TryGetFields(row, out string httpSetCookie, "http.set_cookie",
                            "http2.headers.set_cookie"))
                        {
                            HttpHeaders["Set-Cookie"] = httpSetCookie;
                        }

                        if (TryGetFields(row, out string httpUserAgent, "http.user_agent",
                            "http2.headers.user_agent"))
                        {
                            HttpHeaders["User-Agent"] = httpUserAgent;
                        }

                        if (TryGetFields(row, out string httpReferer, "http.referer", "http2.headers.referer"))
                        {
                            HttpHeaders["Referer"] = httpReferer;
                        }

                        if (TryGetFields(row, out string httpCookie, "http.cookie", "http2.headers.cookie"))
                        {
                            HttpHeaders["Cookie"] = httpCookie;
                        }

                        // parse json
                        payload += "\n";
                        payload += GetFieldOrDefault(row, "json.value.key");
                        payload += GetFieldOrDefault(row, "json.value.string");
                        payload += GetFieldOrDefault(row, "json.value.number");

                        // encoded forms
                        payload += "\n";
                        payload += GetFieldOrDefault(row, "urlencoded-form.key");
                        payload += GetFieldOrDefault(row, "urlencoded-form.value");

                        string tlsCipher = string.Empty;

                        if (isHttps
                            && TryGetField(row, "tls.record.version", out string tlsRecord))
                        {
                            tlsCipher = GetTlsCipher(tlsRecord);

                            if (string.IsNullOrEmpty(tlsCipher)
                                && TryGetField(row, "_ws.col.Protocol", out string protocol))
                            {
                                tlsCipher = protocol;
                            }
                        }

                        // Check for tracking-pixel
                        if (TryGetField(row, "image-gif.image.width", out int gifWidth) && gifWidth == 1
                            && TryGetField(row, "image-gif.image.height", out int gifHeigth) && gifHeigth == 1)
                        {
                            Dictionary<string, List<string>> keywords = new Dictionary<string, List<string>>()
                            {
                                {"Tracking pixel", new List<string>() {"1x1 Web Gif"}}
                            };
                        }

                        return HttpPayload.FromText(payload, LinkedTcpPacket, HttpHeaders, isHttps, tlsCipher);
                    }
                    
                    // layer 5-7 (MQTT)
                    if (TryGetField(row, "mqtt.hdrflags", out string mqttHeaderFlags))
                    {
                        // mqtt metainfo
                        string mqttPayload = $"{GetFieldWithPrefixOrDefault(row, "MQTT Version:", "mqtt.ver")}\n";
                        mqttPayload += $"{GetFieldWithPrefixOrDefault(row, "Topic:", "mqtt.topic")}\n";
                        mqttPayload += $"{GetFieldWithPrefixOrDefault(row, "ClientId:", "mqtt.clientid")}\n";
                        mqttPayload += $"{GetFieldWithPrefixOrDefault(row, "Username:", "mqtt.username")}\n";
                        mqttPayload += $"{GetFieldWithPrefixOrDefault(row, "Password:", "mqtt.passwd")}\n";
                        mqttPayload += $"{GetFieldWithPrefixOrDefault(row, "Password-Length:", "mqtt.passwd_len")}\n";
                        mqttPayload += $"{GetFieldWithPrefixOrDefault(row, "Clean Session Flag:", "mqtt.conflag.cleansess")}\n";
                        mqttPayload += $"{GetFieldWithPrefixOrDefault(row, "Conack ReasonCode:", "mqtt.connack.reason_code")}\n";
                        mqttPayload += $"{GetFieldWithPrefixOrDefault(row, "Session Present:", "mqtt.conack.flags.sp")}\n";

                        string message = GetFieldOrDefault(row, "mqtt.msg");
                        if (message != "") {
                            mqttPayload += $"Message: {Utils.HexStringToASCII(message)}";
                        }
                        return MqttPayload.FromText(mqttPayload, LinkedTcpPacket, mqttHeaderFlags);
                    }
                }
                else
                {
                    Logger.LogAlert("Failed to parse TCP packet"); 
                }
            }
            else
            {
                Logger.LogAlert("Failed to parse IP packet");
            }

            return null;
        }

        private EthernetPacket ParseEthernet(string[] row)
        {
            EthernetPacket LinkedEthernetPacket;
            long ethFrameNumber;
            string ethFrameTime;
            string ethSrc;
            string ethDst;

            TryGetField(row, "frame.number", out ethFrameNumber);
            TryGetField(row, "frame.time", out ethFrameTime);

            if (TryGetField(row, "eth.src", out ethSrc)
                && TryGetField(row, "eth.dst", out ethDst)
                && EthernetPacket.FromText(ethFrameNumber, ethSrc, ethDst, ethFrameTime, out LinkedEthernetPacket)) {
                    return LinkedEthernetPacket;
            } else {
                // Linux Cooked Capture
                TryGetField(row, "sll.src.eth", out ethSrc);
                ethDst = ""; // LCC does not know the destination mac address
                EthernetPacket.FromText(ethFrameNumber, ethSrc, ethDst, ethFrameTime, out LinkedEthernetPacket);
                return LinkedEthernetPacket;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private string FormatPayload(string payload)
        {
            // Clean up tshark output
            if (payload.Contains("Timestamps,"))
            {
                payload = payload.Split("Timestamps,")[1]; // remove timestamps-field preceding the payload
            }

            return payload.Replace("\\r", "\r").Replace("\\n", "\n").Replace("\r\n,\r\n", "\r\n\r\n");
        }

        private List<IPcapngPayload> ParsePacketsCsv(string csvFile)
        {
            Logger.Log("Parsing packet information from .csv...");

            List<IPcapngPayload> payloads = new List<IPcapngPayload>();

            using (TextFieldParser parser = new TextFieldParser(csvFile))
            {
                parser.TextFieldType = FieldType.Delimited;
                parser.SetDelimiters("\t");

                while (!parser.EndOfData)
                {
                    string[] row = parser.ReadFields();

                    if (row?.Length > 0 && TryGetField(row, "text", out string payload))
                    {
                        string tlsPayload = string.Empty;

                        if (TlsEnabled && TryGetField(row, "tls.segment.data", out tlsPayload))
                        {
                            tlsPayload = GetFieldOrDefault(row, "tls.segment.data");
                        }

                        bool isTls = TryGetField(row, "tls.record.length", out string tlsRecordLenght) && !string.IsNullOrWhiteSpace(tlsRecordLenght);

                        payload = FormatPayload(payload);

                        if (isTls)
                        {
                            payload += Utils.HexStringToASCII(tlsPayload.Split(',')[0]);
                        }

                        IPcapngPayload payloadToAdd = BuildPayloadFromCsvRow(row, payload, isTls);

                        if (payloadToAdd != null)
                        {
                            payloads.Add(payloadToAdd);
                        }
                    }
                }
            }

            return payloads;
        }

        private bool RunTsharkWithArgs(string tsharkArgs, string outfile)
        {
            using StreamWriter sw = new StreamWriter(outfile, true);
            Process process = new Process();

            string tsharkExePath;

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                string pathInOwnFolder = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "tshark.exe");
                string pathInProgramFolder = Path.Combine(Environment.GetEnvironmentVariable("ProgramFiles"), "Wireshark", "tshark.exe");

                if (File.Exists(pathInOwnFolder))
                {
                    tsharkExePath = pathInOwnFolder;
                }
                else if (File.Exists(pathInProgramFolder))
                {
                    tsharkExePath = pathInProgramFolder;
                }
                else
                {
                    string enviromentPath = Environment.GetEnvironmentVariable("PATH");
                    string[] paths = enviromentPath.Split(';');

                    tsharkExePath = paths.Select(x => Path.Combine(x, "tshark.exe")).FirstOrDefault(x => File.Exists(x));
                }
            }
            else
            {
                tsharkExePath = "tshark";
            }

            if (string.IsNullOrEmpty(tsharkExePath))
            {
                Logger.LogNegative("tshark not found. aborting analysis...");
                return false;
            }

            process.StartInfo.FileName = tsharkExePath;
            process.StartInfo.Arguments = tsharkArgs;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.CreateNoWindow = true; // hide output of tshark
            process.StartInfo.RedirectStandardOutput = true;

            process.OutputDataReceived += new DataReceivedEventHandler((sender, e) =>
            {
                if (!string.IsNullOrEmpty(e.Data))
                {
                    sw.WriteLine(e.Data);
                }
            });

            process.Start();
            process.BeginOutputReadLine();
            process.WaitForExit();
            sw.Close();

            return true;
        }
    }
}