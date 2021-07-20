using System;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.IO;

namespace OTAlyzer.AnalyticsCore.Traffic.Mitmproxy.Blocks
{
    public class MitmBlock : IAnalyzeable
    {
        [JsonProperty("client_conn")]
        public JObject ClientConnection { get; set; }

        [JsonProperty("error")]
        public JObject Error { get; set; }

        [JsonIgnore]
        public int Length => GetString().Length;

        [JsonProperty("request")]
        public JObject Request { get; set; }

        [JsonProperty("response")]
        public JObject Response { get; set; }

        [JsonProperty("server_conn")]
        public JObject ServerConnection { get; set; }

        [JsonProperty("type")]
        public string Type { get; set; }

        public string GetString()
        {
            // This is the fastest way to serialize. See https://www.newtonsoft.com/json/help/html/Performance.htm
            StringWriter sw = new StringWriter();
            JsonTextWriter writer = new JsonTextWriter(sw);
            // {
            writer.WriteStartObject();
            writer.WritePropertyName("client_conn");
            writer.WriteValue(ClientConnection.ToString(Formatting.None));
            if (Error != null)
            {
                writer.WritePropertyName("error");
                writer.WriteValue(Error.ToString(Formatting.None));
            }
            writer.WritePropertyName("request");
            writer.WriteValue(Request.ToString(Formatting.None));
            if (Response != null)
            {
                writer.WritePropertyName("response");
                writer.WriteValue(Response.ToString(Formatting.None));
            }
            writer.WritePropertyName("server_conn");
            writer.WriteValue(ServerConnection.ToString(Formatting.None));
            writer.WritePropertyName("type");
            writer.WriteValue(Type);
            // }
            writer.WriteEndObject();

            return sw.ToString();
        }
    }
}