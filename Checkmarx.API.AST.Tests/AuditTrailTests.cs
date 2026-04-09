using Microsoft.Extensions.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace Checkmarx.API.AST.Tests
{
    [TestClass]
    public class AuditTrailTests
    {
        public static IConfigurationRoot Configuration { get; private set; }

        private static ASTClient astclient;

        private static Guid projectId = new Guid("61039804-3d8f-4efa-8f42-86ec9c253010");

        [ClassInitialize]
        public static void InitializeTest(TestContext testContext)
        {
            var builder = new ConfigurationBuilder()
                .AddUserSecrets<AuditTrailTests>();

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
        public void GetAuditTrailtTest()
        {
            var auditEvents = astclient.GetAllAuditEvents(new DateTime(2026, 01, 01), new DateTime(2026, 04, 03));

            foreach (var auditEvent in auditEvents)
            {
                Trace.WriteLine(Newtonsoft.Json.JsonConvert.SerializeObject(auditEvent));
            }

        }

    }
}
