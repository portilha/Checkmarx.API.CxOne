using Checkmarx.API.AST.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;

namespace Checkmarx.API.AST.Tests
{
    [TestClass]
    public class ProcessTests
    {
        private static ASTClient astclient;

        public static IConfigurationRoot Configuration { get; private set; }

        [ClassInitialize]
        public static void InitializeTest(TestContext testContext)
        {
            var builder = new ConfigurationBuilder()
                .AddUserSecrets<ProjectTests>();

            Configuration = builder.Build();

            string astServer = Configuration["ASTServer"];
            string accessControl = Configuration["AccessControlServer"];

            astclient = new ASTClient(
                new System.Uri(astServer),
                new System.Uri(accessControl),
                Configuration["Tenant"],
                Configuration["API_KEY"]);
        }

        [TestMethod]
        public void GetPresetDetailsTest()
        {
            var properties = typeof(PresetDetails).GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.GetProperty);

            foreach (var item in astclient.GetAllPresetsDetails())
            {
                foreach (var property in properties)
                {
                    Trace.WriteLine($"{property.Name} = {property.GetValue(item)?.ToString()}");
                }

                foreach (var queryId in PresetManagement.GetAllQueryIdsFromPreset(item))
                {
                    Trace.WriteLine($"\t{queryId}");
                }

                Trace.WriteLine("---");
            }
        }

        [TestMethod]
        public void GetQueriesTest()
        {
            var properties = typeof(Services.SASTQueriesAudit.Queries).GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.GetProperty);

            foreach (var item in astclient.SASTQueriesAudit.QueriesAllAsync().Result)
            {
                foreach (var property in properties)
                {
                    Trace.WriteLine($"{property.Name} = {property.GetValue(item)?.ToString()}");
                }

                Trace.WriteLine("---");
            }
        }

        [TestMethod]
        public void QueriesForProjectTest()
        {
            var listOfQueries = astclient.GetQueries(astclient.Projects.GetListOfProjectsAsync().Result.Projects.First().Id);

            Dictionary<string, Services.SASTQueriesAudit.Queries> keys = new Dictionary<string, Services.SASTQueriesAudit.Queries>();

            var properties = typeof(Services.SASTQueriesAudit.Queries).GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.GetProperty);

            foreach (var query in listOfQueries)
            {
                if (!keys.ContainsKey(query.Key))
                    keys.Add(query.Key, query.Value);
                else
                {
                    foreach (var property in properties)
                    {
                        Trace.WriteLine($"{property.Name} = {property.GetValue(keys[query.Key])?.ToString()}");
                    }
                    Trace.WriteLine("---");

                    foreach (var property in properties)
                    {
                        Trace.WriteLine($"{property.Name} = {property.GetValue(query)?.ToString()}");
                    }
                    Trace.WriteLine("---");
                    Trace.WriteLine("========================");
                }
            }
        }

        [TestMethod]
        public void LogEngineTest()
        {
            Trace.WriteLine(astclient.GetSASTScanLog(astclient.GetLastScan(astclient.Projects.GetListOfProjectsAsync().Result.Projects.Last().Id).Id));
        }


        [TestMethod]
        public void ListMainBranchesTest()
        {
            foreach (var project in astclient.GetAllProjectsDetails())
            {
                Trace.WriteLine($"{project.Name};{project.Id};{project.MainBranch ?? "null"}");
            }
        }


        [TestMethod]
        public void KicsGetHistoryTest()
        {
            var properties = typeof(Predicate).GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.GetProperty);

            foreach (KICSPredicateHistory item in astclient.KicsResultsPredicates.ReadAsync("ed440168d16f631592d46e6511d6db66ea1927402a550aa04c48a3709bf4023d",
                [new Guid("1c724868-72fa-4bfe-aca5-6c9096b48408")]).Result.PredicateHistoryPerProject)
            {
                foreach (Predicate predicate in item.Predicates.Reverse())
                {
                    foreach (var property in properties)
                    {
                        Trace.WriteLine($"{property.Name} = {property.GetValue(predicate)?.ToString()}");
                    }
                    Trace.WriteLine("---");
                }
            }
        }

        [TestMethod]
        public void KicsPostHistoryTest()
        {
            KICSPredicateHistory item = astclient.KicsResultsPredicates.ReadAsync("ed440168d16f631592d46e6511d6db66ea1927402a550aa04c48a3709bf4023d", [new Guid("1c724868-72fa-4bfe-aca5-6c9096b48408")]).Result.PredicateHistoryPerProject.SingleOrDefault();

            var newHistory = item.Predicates.Reverse();
            foreach (var property in newHistory)
            {
                property.SimilarityId = "4816e8d3444a0b6e75ca263b7e6e2f7e867393a03848608efc028a86bd2cde13";

                if (!string.IsNullOrWhiteSpace(property.Comment))
                    property.Comment = $"{property.CreatedBy} added new comment: \"{property.Comment}\"";
            }

            astclient.KicsResultsPredicates.UpdateAsync(newHistory).Wait();
        }


        [TestMethod]
        public void SASTClearResultHistoryTest()
        {
            var historyPerProject = astclient.SASTResultsPredicates.GetPredicatesBySimilarityIDAsync("-717279067").Result.PredicateHistoryPerProject;

            Assert.IsTrue(historyPerProject.Any());

            var singleHistoryPerProject = astclient.SASTResultsPredicates.GetPredicatesBySimilarityIDAsync("-717279067", [new Guid("439ab490-a491-4e81-b36d-fefdb5113e22")]).Result.PredicateHistoryPerProject;

            Assert.IsTrue(singleHistoryPerProject.SingleOrDefault() != null);
        }

        [TestMethod]
        public void RecalculateSummaryCountersTest()
        {
            astclient.RecalculateSummaryCounters(new Guid("c6b124a3-8aa0-4cd1-8b40-b1a847759547"), new Guid("6b11cd1a-b85e-46e9-96ef-341ecea45f04"));
        }
    }
}
