using System.IO;
using NUnit.Framework;

namespace ITfoxtec.Identity.Saml2.Tests
{
    public static class TestFile
    {
        public static string MapPath(string relativePath) => Path.Combine(TestContext.CurrentContext.TestDirectory, relativePath);
    }
}
