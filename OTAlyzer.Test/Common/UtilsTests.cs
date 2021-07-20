using Microsoft.VisualStudio.TestTools.UnitTesting;
using OTAlyzer.Common;
using System;

namespace OTAlyzer.Test
{
    [TestClass]
    public class UtilsTests
    {
        [TestMethod]
        public void BuildTrafficCaptureName()
        {
            Assert.AreEqual("A01_02.pcapng", Utils.BuildTrafficCaptureName("Android", 1, 2, ".pcapng"));
            Assert.AreEqual("I02_03.pcapng", Utils.BuildTrafficCaptureName("iOS", 2, 3, ".pcapng"));
        }

        [TestMethod]
        public void ByteArrayToHexViaLookupTable()
        {
            byte[] bytes = { 0x1, 0x2, 0x4, 0x8 };
            Assert.AreEqual("01020408", Utils.ByteArrayToString(bytes));
        }

        [TestMethod]
        public void ByteArrayToString()
        {
            byte[] bytes = { 0x1, 0x2, 0x4, 0x8 };
            Assert.AreEqual("01020408", Utils.ByteArrayToString(bytes));
        }

        [TestMethod]
        public void Capitalize()
        {
            string test = "test";
            Assert.AreEqual("Test", Utils.Capitalize(test));

            test = "tEST";
            Assert.AreEqual("TEST", Utils.Capitalize(test));

            test = "t";
            Assert.AreEqual("T", Utils.Capitalize(test));

            test = "Test";
            Assert.AreEqual("Test", Utils.Capitalize(test));

            test = "TEST";
            Assert.AreEqual("TEST", Utils.Capitalize(test));
        }

        [TestMethod]
        public void CharToHexValue()
        {
            Assert.AreEqual(10, Utils.CharToHexValue('A'));
            Assert.AreEqual(11, Utils.CharToHexValue('B'));
            Assert.AreEqual(12, Utils.CharToHexValue('C'));
            Assert.AreEqual(13, Utils.CharToHexValue('D'));
            Assert.AreEqual(14, Utils.CharToHexValue('E'));
            Assert.AreEqual(15, Utils.CharToHexValue('F'));
        }

        [TestMethod]
        public void GenerateRandomString()
        {
            string result = Utils.GenerateRandomString(12);
            Assert.IsTrue(result.Length == 12);
        }

        [TestMethod]
        public void HexStringToByteArray()
        {
            const string s = "427A42";
            string result = Utils.HexStringToASCII(s);

            Assert.AreEqual("BzB", result);
        }

        [TestMethod]
        public void ImageToBase64()
        {
            const string base64Image = "data:img/jpg;base64,QUJDREVG";
            Assert.AreEqual(base64Image, ImageUtils.ImageToBase64(Convert.FromBase64String("QUJDREVG"), "img/jpg"));
        }

        [TestMethod]
        public void MacAddressToString()
        {
            byte[] rawMac = { 0x33, 0x7A, 0x42, 0x50, 0x4F, 0x5A };
            const string mac = "33:7A:42:50:4F:5A";
            Assert.AreEqual(mac, Utils.MacAddressToString(rawMac));
        }

        [TestMethod]
        public void PasswordHashing()
        {
            const string password = "test1234";
            PasswordUtils.HashPassword(password, out string base64Hash, out string base64Salt);
            PasswordUtils.HashPassword(password, out string base64Hash2, out _, Convert.FromBase64String(base64Salt));

            Assert.AreEqual(base64Hash, base64Hash2);

            PasswordUtils.HashPassword(password, out string base64Hash3, out _, Convert.FromBase64String("HAm+tDk727rtaeqrgygyPA=="));
            Assert.AreEqual(base64Hash3, "Hn3OmTwkA39a7i56kpuHQL+IhGA=");
        }
    }
}