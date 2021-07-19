using System;
using System.Net;

namespace OTAlyzer.Common
{
    public static class ImageUtils
    {
        public static string DownloadImageAsBase64(string url, string contentType)
        {
            using WebClient webClient = new WebClient();
            return ImageToBase64(webClient.DownloadData(url), contentType);
        }

        public static string ImageToBase64(byte[] rawImageData, string contentType)
        {
            return $"data:{contentType};base64,{Convert.ToBase64String(rawImageData)}";
        }
    }
}