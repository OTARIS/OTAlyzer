using Microsoft.VisualStudio.TestTools.UnitTesting;
using OTAlyzer.AnalyticsWorker.Options;
using System.IO;

namespace OTAlyzer.Test.Worker
{
    [TestClass]
    public class OptionsBuilderTests
    {
        [TestMethod]
        public void InvalidArgument()
        {
            string[] testArgs = new string[]
            {
                "-z value#that_never-will.be+used?and`is/trash"
            };

            bool status = OptionsBuilder.TryParseCommandLineArguments(testArgs, out OtalyzerOptions otalyzerOptions);

            Assert.IsFalse(status);
        }

        [TestMethod]
        public void InvalidFile()
        {
            string[] testArgs = new string[]
            {
               "-k", "fileThatNotExists.mp5",
               "-s", "fileThatNotExists.mp5",
               "-p", "fileThatNotExists.mp5",
               "--tls", "fileThatNotExists.mp5",
               "--filename", "fileThatNotExists.mp5",
               "--severity-threshold", "8",
               "--blacklists", "fileThatNotExists.mp5",
            };

            bool status = OptionsBuilder.TryParseCommandLineArguments(testArgs, out OtalyzerOptions otalyzerOptions);

            Assert.IsFalse(status);
        }

        [TestMethod]
        public void ValidArguments()
        {
            // generate some temp files for testing
            string[] tempFiles = new string[6];

            for (int i = 0; i < tempFiles.Length; ++i)
            {
                tempFiles[i] = Path.GetTempFileName();
            }

            string[] testArgs = new string[]
            {
               "-k", $"{tempFiles[0]}",
               "-s", $"{tempFiles[1]}",
               "-p", $"{tempFiles[2]}",
               "--tls", $"{tempFiles[3]}",
               "--filename", $"{tempFiles[4]}", // will become test5.json
               "--severity-threshold", "8",
               "--blacklists", $"{tempFiles[5]}",
            };

            bool status = OptionsBuilder.TryParseCommandLineArguments(testArgs, out OtalyzerOptions otalyzerOptions);

            Assert.IsTrue(status);

            Assert.AreEqual(tempFiles[0], otalyzerOptions.KeywordListFile);
            Assert.AreEqual(tempFiles[1], otalyzerOptions.SeverityLevelFile);
            Assert.AreEqual(tempFiles[2], otalyzerOptions.TrafficCaptureFile);
            Assert.AreEqual(tempFiles[3], otalyzerOptions.Sslkeylogfile);
            Assert.AreEqual(true, otalyzerOptions.DecryptTls);
            Assert.AreEqual($"{tempFiles[4]}.json", otalyzerOptions.OutputFile);
            Assert.IsTrue(otalyzerOptions.BlacklistFiles.Contains(tempFiles[5]));

            // cleanup
            for (int i = 0; i < tempFiles.Length; ++i)
            {
                File.Delete(tempFiles[i]);
            }
        }
    }
}