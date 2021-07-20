using Microsoft.VisualStudio.TestTools.UnitTesting;
using OTAlyzer.AnalyticsCore.Analyzers;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace OTAlyzer.Test.Core.Analyzers
{
    [TestClass]
    public class TsharkWrapperTests
    {
        [TestMethod]
        public void SampleCsvParsing()
        {
            // generate a sample csv like this: 0\t1\t2\t...
            StringBuilder sb = new StringBuilder();

            for (int i = 0; i < TsharkWrapper.TsharkFields.Count; ++i)
            {
                sb.Append(i).Append('\t');
            }

            string samplePath = Path.GetTempFileName();
            File.WriteAllText(samplePath, sb.ToString());

            TsharkWrapper tsharkWrapper = new TsharkWrapper(string.Empty, false, string.Empty);
            bool result = tsharkWrapper.ParseTsharkResultsFile(samplePath);

            Assert.IsTrue(result);

            File.Delete(samplePath);
        }

        private string[] GenerateSampleArray()
        {
            string[] sb = new string[TsharkWrapper.TsharkFields.Count];

            for (int i = 0; i < TsharkWrapper.TsharkFields.Count; ++i)
            {
                sb[i] = i.ToString();
            }

            return sb;
        }

        private string[] GenerateSampleArrayFloat()
        {
            string[] sb = new string[TsharkWrapper.TsharkFields.Count];

            for (int i = 0; i < TsharkWrapper.TsharkFields.Count; ++i)
            {
                sb[i] = ((float)i).ToString();
            }

            return sb;
        }

        [TestMethod]
        public void TryGetFieldValid()
        {
            string[] sb = GenerateSampleArray();
            TsharkWrapper tsharkWrapper = new TsharkWrapper(string.Empty, false, string.Empty);

            for (int i = 0; i < TsharkWrapper.TsharkFields.Count; ++i)
            {
                bool getFieldResult = tsharkWrapper.TryGetField(sb, TsharkWrapper.TsharkFields.Keys.ElementAt(i), out string value);

                if (getFieldResult)
                {
                    Assert.AreEqual(i.ToString(), value);
                }
            }
        }

        [TestMethod]
        public void TryGetFieldGenericIntValid()
        {
            string[] sb = GenerateSampleArray();
            TsharkWrapper tsharkWrapper = new TsharkWrapper(string.Empty, false, string.Empty);

            for (int i = 0; i < TsharkWrapper.TsharkFields.Count; ++i)
            {
                bool getFieldResult = tsharkWrapper.TryGetField(sb, TsharkWrapper.TsharkFields.Keys.ElementAt(i), out int value);

                if (getFieldResult)
                {
                    Assert.AreEqual(i, value);
                }
            }
        }

        [TestMethod]
        public void TryGetFieldGenericFloatValid()
        {
            string[] sb = GenerateSampleArrayFloat();
            TsharkWrapper tsharkWrapper = new TsharkWrapper(string.Empty, false, string.Empty);

            for (int i = 0; i < TsharkWrapper.TsharkFields.Count; ++i)
            {
                bool getFieldResult = tsharkWrapper.TryGetField(sb, TsharkWrapper.TsharkFields.Keys.ElementAt(i), out float value);

                if (getFieldResult)
                {
                    Assert.AreEqual(i, value);
                }
            }
        }

        [TestMethod]
        public void TryGetFieldGenericDoubleValid()
        {
            string[] sb = GenerateSampleArrayFloat();
            TsharkWrapper tsharkWrapper = new TsharkWrapper(string.Empty, false, string.Empty);

            for (int i = 0; i < TsharkWrapper.TsharkFields.Count; ++i)
            {
                bool getFieldResult = tsharkWrapper.TryGetField(sb, TsharkWrapper.TsharkFields.Keys.ElementAt(i), out double value);

                if (getFieldResult)
                {
                    Assert.AreEqual(i, value);
                }
            }
        }

        [TestMethod]
        public void TryGetFieldsValid()
        {
            string[] sb = GenerateSampleArray();
            TsharkWrapper tsharkWrapper = new TsharkWrapper(string.Empty, false, string.Empty);

            for (int i = 0; i < TsharkWrapper.TsharkFields.Count; ++i)
            {
                // should always use the second params string
                bool getFieldResult = tsharkWrapper.TryGetFields(sb, out string value, "invalidField", TsharkWrapper.TsharkFields.Keys.ElementAt(i));

                if (getFieldResult)
                {
                    Assert.AreEqual(i.ToString(), value);
                }
            }
        }

        [TestMethod]
        public void GetFieldOrDefault()
        {
            string[] sb = GenerateSampleArray();
            TsharkWrapper tsharkWrapper = new TsharkWrapper(string.Empty, false, string.Empty);

            const string defaultValue = "invalidField";

            for (int i = 0; i < TsharkWrapper.TsharkFields.Count; ++i)
            {
                // should always use the default
                string getFieldResult = tsharkWrapper.GetFieldOrDefault(sb, "fakeField", defaultValue);

                Assert.AreEqual(getFieldResult, defaultValue);
            }
        }
    }
}
