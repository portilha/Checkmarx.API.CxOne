using Checkmarx.API.AST.Enums;
using Checkmarx.API.AST.Models;
using Checkmarx.API.AST.Services.Configuration;
using Checkmarx.API.AST.Services.SASTResults;
using Checkmarx.API.AST.Services.SASTScanResultsCompare;
using Checkmarx.API.AST.Services.Scans;
using Keycloak.Net.Models.Root;
using Microsoft.Extensions.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Diagnostics;
using System.Linq;

namespace Checkmarx.API.AST.Tests
{
    [TestClass]
    public class AuditTests
    {
        public static IConfigurationRoot Configuration { get; private set; }

        private static ASTClient astclient;

        private static Guid projectId = new Guid("61039804-3d8f-4efa-8f42-86ec9c253010");

        [ClassInitialize]
        public static void InitializeTest(TestContext testContext)
        {
            var builder = new ConfigurationBuilder()
                .AddUserSecrets<AuditTests>();

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

        // Run this alongside ListCxQueriesTest, ListTenantQueriesTest, ListApplicationLevelQueriesTest
        // and ListProjectQueriesTest, one by one: Cx and Tenant are genuinely tenant-wide scopes, so
        // their counts here must match those individual tests exactly. Application and Project here
        // are summed across every project in the tenant, while the individual tests below are scoped
        // to just the one known `projectId` — those two only match if that project is the sole
        // contributor for that level tenant-wide; otherwise this total is expected to be higher.
        [TestMethod]
        public void ListAllQueriesTest()
        {
            var allQueries = astclient.GetAllQueries().Values;

            int cxCount = allQueries.Count(q => q.Level == ASTClient.Query_Level_Cx);
            int tenantCount = allQueries.Count(q => q.Level == ASTClient.Query_Level_Tenant);
            int applicationCount = allQueries.Count(q => q.Level == ASTClient.Query_Level_Application);
            int projectCount = allQueries.Count(q => q.Level == ASTClient.Query_Level_Project);

            Trace.WriteLine($"Total queries: {allQueries.Count()}");
            Trace.WriteLine($"Cx: {cxCount}");
            Trace.WriteLine($"Tenant: {tenantCount}");
            Trace.WriteLine($"Application: {applicationCount}");
            Trace.WriteLine($"Project: {projectCount}");
        }

        [TestMethod]
        public void ListCxQueriesTest()
        {
            var cxQueries = astclient.GetCxLevelQueries().Values;

            Trace.WriteLine($"Cx queries: {cxQueries.Count()}");
        }

        [TestMethod]
        public void ListTenantQueriesTest()
        {
            var tenantQueries = astclient.GetTenantLevelQueries().Values;

            Trace.WriteLine($"Tenant queries: {tenantQueries.Count()}");
        }

        [TestMethod]
        public void ListApplicationLevelQueriesTest()
        {
            var applicationQueries = astclient.GetApplicationLevelQueries(projectId).Values;

            Trace.WriteLine($"Application queries visible through project {projectId}: {applicationQueries.Count()}");
        }

        [TestMethod]
        public void ListCxAndTenantQueriesTest()
        {
            string language = "CSharp";
            string name = "Log_Forging";

            var allCxAndTenantQueries = astclient.GetQueries().Values;
            var allProjectQueriesLogForging = allCxAndTenantQueries.Where(q => q.Lang == language && q.Name == name);

            Trace.WriteLine($"List of ALL Cx and Tenant queries ({allCxAndTenantQueries.Count()}):");
            Trace.WriteLine("");
            foreach (var query in allCxAndTenantQueries)
                Trace.WriteLine($"ID: {query.Id} | Level: {query.Level} | Language: {query.Lang} | Name: {query.Name}");

            Trace.WriteLine("");
            Trace.WriteLine($"List of ALL Cx and Tenant queries for {language} {name} ({allProjectQueriesLogForging.Count()}):");
            Trace.WriteLine("");
            foreach (var query in allProjectQueriesLogForging)
                Trace.WriteLine($"ID: {query.Id} | Level: {query.Level} | Language: {query.Lang} | Name: {query.Name}");

            Assert.AreEqual(allProjectQueriesLogForging.Single().Level, ASTClient.Query_Level_Cx);
        }


        [TestMethod]
        public void ListAllProjectQueriesTest()
        {
            string language = "CSharp";
            string name = "Log_Forging";

            var allProjectQueries = astclient.GetQueries(projectId).Values;
            var allProjectQueriesLogForging = allProjectQueries.Where(q => q.Lang == language && q.Name == name);

            Trace.WriteLine($"List of Cx, Tenant and Project queries ({allProjectQueries.Count()}):");
            Trace.WriteLine("");
            foreach (var query in allProjectQueries)
                Trace.WriteLine($"ID: {query.Id} | Level: {query.Level} | Language: {query.Lang} | Name: {query.Name}");

            Trace.WriteLine("");
            Trace.WriteLine($"List of {language} {name} queries ({allProjectQueriesLogForging.Count()}):");
            Trace.WriteLine("");
            foreach (var query in allProjectQueriesLogForging)
                Trace.WriteLine($"ID: {query.Id} | Level: {query.Level} | Language: {query.Lang} | Name: {query.Name}");

            Assert.AreEqual(allProjectQueriesLogForging.Single().Level, ASTClient.Query_Level_Project);
        }

        // Tenant-wide Application-level discovery (ranking candidate projects per Application,
        // retrying across sessions, etc.) is business logic, not a wrapper concern — it lives in
        // Checkmarx.Model.CxOne.CxOneInstance.GetApplicationLevelQueries(), not here. This test only
        // exercises the low-level primitive ASTClient itself is responsible for: reading the
        // Application-level branch visible through a single, known project's session.
        [TestMethod]
        public void ListApplicationQueriesTest()
        {
            var applicationQueries = astclient.GetApplicationLevelQueriesFromSession(projectId);

            Trace.WriteLine($"List of Application queries visible through project {projectId} ({applicationQueries.Count()}):");
            Trace.WriteLine("");
            foreach (var query in applicationQueries)
                Trace.WriteLine($"ID: {query.Id} | Level: {query.Level} | Language: {query.Metadata?.Language} | Name: {query.Name} | Has Source: {!string.IsNullOrEmpty(query.Source)}");
        }

        [TestMethod]
        public void ListProjectQueriesTest()
        {
            var projectQueries = astclient.GetProjectLevelQueries(projectId).Values;

            Trace.WriteLine($"Project queries for {projectId}: {projectQueries.Count()}");
        }

        [TestMethod]
        public void GetQuerySourceTest()
        {
            string language = "Java";
            string name = "Code_Injection";

            var projLevelSource = astclient.GetQuerySource(language, name, projectId);
            var tenantLevelSource = astclient.GetQuerySource(language, name);
        }

        [TestMethod]
        public void OverrideQueryForTenantTest()
        {
            string language = "CSharp";
            string name = "Check_HSTS_Configuration";
            string querySource = "result = base.Check_HSTS_Configuration();";

            astclient.OverrideTenantQuerySource(language, name, querySource);
        }

        [TestMethod]
        public void OverrideQueryForApplicationTest()
        {
            string language = "CSharp";
            string name = "Heap_Inspection";
            string querySource = "result = base.Heap_Inspection(); // Test";

            astclient.OverrideApplicationQuerySource(projectId, language, name, querySource);
        }

        [TestMethod]
        public void OverrideQueryForProjectTest()
        {
            string language = "CSharp";
            string name = "Heap_Inspection";
            string querySource = "result = base.Heap_Inspection(); // Test";

            astclient.OverrideProjectQuerySource(projectId, language, name, querySource);
        }

        [TestMethod]
        public void CreateQueryForTenantTest()
        {
            var queries = astclient.GetCxLevelQueries().Values;
            var query = queries.FirstOrDefault(q => q.Lang == "CSharp" && q.Group == "General" && q.Name == "Check_Web_Application");

            Assert.IsNotNull(query);

            astclient.CreateTenantQuery(query.Lang, query.Name, query.Group, query.Severity, "base.Check_Web_Application();", query.IsExecutable);
        }

        [TestMethod]
        public void UpdateQuerySeverityTest()
        {
            var queries = astclient.GetCxLevelQueries().Values;
            var query = queries.FirstOrDefault(q => q.Lang == "CSharp" && q.Group == "General" && q.Name == "Check_HSTS_Validation");

            Assert.IsNotNull(query);

            astclient.SetTenantQuerySeverity(query.Lang, query.Name, ASTClient.QuerySeverity.Info);
        }

        [TestMethod]
        public void DeleteProjectQueryTest()
        {
            string language = "Java";
            string name = "XPath_Injection";

            astclient.DeleteProjectQuery(projectId, language, name);
        }

        [TestMethod]
        public void DeleteTenantQueryTest()
        {
            string language = "CSharp";
            string name = "Tutorial_CxDefaultQuery";

            astclient.DeleteTenantQuery(language, name);
        }
    }
}