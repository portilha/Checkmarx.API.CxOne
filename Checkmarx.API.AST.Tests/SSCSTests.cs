using Checkmarx.API.AST.Models.SCA;
using Microsoft.Extensions.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Checkmarx.API.AST.Tests
{
    [TestClass]
    public class SSCSTests
    {
        public static IConfigurationRoot Configuration { get; private set; }
        private static ASTClient astclient;

        [ClassInitialize]
        public static void InitializeTest(TestContext testContext)
        {
            var builder = new ConfigurationBuilder()
                .AddUserSecrets<SCATests>();

            Configuration = builder.Build();

            if (!string.IsNullOrWhiteSpace(Configuration["API_KEY"]))
            {
                astclient = new ASTClient(
                new System.Uri(Configuration["ASTServer"]),
                new System.Uri(Configuration["AccessControlServer"]),
                Configuration["Tenant"],
                Configuration["API_KEY"]);
            }
            else
            {
                astclient = new ASTClient(
                new System.Uri(Configuration["ASTServer"]),
                new System.Uri(Configuration["AccessControlServer"]),
                Configuration["Tenant"],
                Configuration["ClientId"],
                Configuration["ClientSecret"]);
            }
        }

        [TestMethod]
        public void UpdatePackageStateTest()
        {
            //var scanDetails = astclient.GetScanDetails(Guid.Parse("b13f9a07-e893-4535-8f63-505c3658fe07"));
            //var sscsVulnerabilities = scanDetails.SSCSVulnerabilities;

            Guid projectId = Guid.Parse("c9466ec7-c6d7-4a64-b584-9438d29dfcc9");
            Guid scanId = Guid.Parse("b13f9a07-e893-4535-8f63-505c3658fe07");

            var results = astclient.GetSSCSResults(projectId, scanId);

            foreach (var (group, pages) in results)
            {
                var totalCount = pages.Sum(p => p.TotalCount);
                Console.WriteLine($"{group.ColumnValue}: {totalCount} entries");
            }
        }
    }
}
