using Microsoft.VisualStudio.TestTools.UnitTesting;
using OTAlyzer.AnalyticsCore.AppStore.Android.Playstore;
using System;

namespace OTAlyzer.Test
{
    [TestClass]
    public class AppstoreParserTests
    {
        [TestMethod]
        public void AppstoreGoogleApp()
        {
            // unused at the moment const string URL = "https://apps.apple.com/de/app/google/id284815942";
            //
            // AppstoreParser appstoreParser = new AppstoreParser(URL);
            //
            // if (appstoreParser.TryParse(out AppstoreEntry appstoreEntry)) {
            // Assert.AreEqual("Google LLC", appstoreEntry.Developer); Assert.AreEqual("Google", appstoreEntry.Name);
            //
            // // other stuff may change so its hard to test here } else { Assert.Fail(); }
        }

        [TestMethod]
        public void InvalidUrl()
        {
            const string URL = "https://google.de";

            try
            {
                PlaystoreParser playstoreParser = new PlaystoreParser(URL);
            }
            catch (Exception ex)
            {
                Assert.IsInstanceOfType(ex, typeof(ArgumentException));
            }
        }

        [TestMethod]
        public void PlaystoreGoogleApp()
        {
            const string URL = "https://play.google.com/store/apps/details?id=com.google.android.googlequicksearchbox&hl=de";

            PlaystoreParser playstoreParser = new PlaystoreParser(URL);
            Assert.AreEqual("com.google.android.googlequicksearchbox", playstoreParser.PackageName);

            if (playstoreParser.TryParse(out PlaystoreEntry playstoreEntry))
            {
                Assert.AreEqual("Google LLC", playstoreEntry.Developer);
                Assert.AreEqual("Google", playstoreEntry.Name);

                // other stuff may change so its hard to test here
            }
            else
            {
                Assert.Fail();
            }
        }
    }
}