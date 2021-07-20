using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace OTAlyzer.AnalyticsCore.Misc
{
    public static class MitmproxyJsonDump
    {
        public static string CommandTemplate => $"-r \"{{0}}\" -s \"{ScriptFile}\" --set jsonfilename=\"{{1}}\" -n";

        public static string ScriptFile => Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Misc", "jsondump.py");

        public static bool ConvertMitmFileToJson(string inputFile, out string outputFile)
        {
            outputFile = $"{Path.GetDirectoryName(inputFile)}{Path.DirectorySeparatorChar}{Path.GetFileNameWithoutExtension(inputFile)}.json";

            string enviromentPath = Environment.GetEnvironmentVariable("PATH");
            string[] paths = enviromentPath.Split(';');
            string mitmdumpExePath;

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                mitmdumpExePath = paths.Select(x => Path.Combine(x, "mitmdump.exe")).FirstOrDefault(x => File.Exists(x));
            }
            else
            {
                mitmdumpExePath = "mitmdump";
            }

            if (string.IsNullOrEmpty(mitmdumpExePath))
            {
                return false;
            }

            string arguments = string.Format(CommandTemplate, inputFile, outputFile);

            Process process = new Process();
            process.StartInfo.FileName = mitmdumpExePath;
            process.StartInfo.Arguments = arguments;
            process.StartInfo.UseShellExecute = true;
            process.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            process.StartInfo.CreateNoWindow = true;

            process.Start();
            process.WaitForExit();

            return File.Exists(outputFile);
        }
    }
}