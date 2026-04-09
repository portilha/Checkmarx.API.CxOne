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

        [TestMethod]
        public void ListAllQueriesTest()
        {
            astclient.GetQueries(projectId);

            var queries = astclient.GetAllQueries();
            Trace.WriteLine($"List of ALL queries ({queries.Count()}):");
            Trace.WriteLine("");
            foreach (var query in queries)
                Trace.WriteLine($"ID: {query.Id} | Level: {query.Level} | Language: {query.Lang} | Name: {query.Name}");
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

        [TestMethod]
        public void ListCxQueriesTest()
        {
            var cxQueries = astclient.GetCxLevelQueries().Values;

            Trace.WriteLine($"List of Cx queries ({cxQueries.Count()}):");
            Trace.WriteLine("");
            foreach (var query in cxQueries)
                Trace.WriteLine($"ID: {query.Id} | Level: {query.Level} | Language: {query.Lang} | Name: {query.Name}");
        }

        [TestMethod]
        public void ListTenantQueriesTest()
        {
            var tenantQueries = astclient.GetTenantLevelQueries().Values;

            Trace.WriteLine($"List of Tenant queries ({tenantQueries.Count()}):");
            Trace.WriteLine("");
            foreach (var query in tenantQueries)
                Trace.WriteLine($"ID: {query.Id} | Level: {query.Level} | Language: {query.Lang} | Name: {query.Name}");
        }

        [TestMethod]
        public void ListProjectQueriesTest()
        {
            var projectQueries = astclient.GetProjectLevelQueries(projectId).Values;

            Trace.WriteLine($"List of Project queries ({projectQueries.Count()}):");
            Trace.WriteLine("");
            foreach (var query in projectQueries)
                Trace.WriteLine($"ID: {query.Id} | Level: {query.Level} | Language: {query.Lang} | Name: {query.Name}");
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
            //string language = "CSharp";
            //string name = "Test_Query_To_Delete";
            //string querySource = "result = base.Check_HSTS_Configuration();";

            string language = "Apex";
            string name = "Hardcoded_Password";
            string querySource = "result = base.Hardcoded_Password();";

            astclient.OverrideTenantQuerySource(language, name, querySource);
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