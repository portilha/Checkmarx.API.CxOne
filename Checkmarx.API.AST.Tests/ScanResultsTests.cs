using Checkmarx.API.AST.Enums;
using Checkmarx.API.AST.Models;
using Checkmarx.API.AST.Models.Report;
using Checkmarx.API.AST.Services;
using Checkmarx.API.AST.Services.KicsResults;
using Checkmarx.API.AST.Services.Reports;
using Checkmarx.API.AST.Services.SASTMetadata;
using Checkmarx.API.AST.Services.SASTResults;
using Checkmarx.API.AST.Services.SASTResultsPredicates;
using Checkmarx.API.AST.Services.Scans;
using Flurl.Util;
using Keycloak.Net.Models.Root;
using Microsoft.Extensions.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Microsoft.VisualStudio.TestTools.UnitTesting.Logging;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;

namespace Checkmarx.API.AST.Tests
{
    [TestClass]
    public class ScanResultsTests
    {

        private static ASTClient astclient;

        public static IConfigurationRoot Configuration { get; private set; }


        [ClassInitialize]
        public static void InitializeTest(TestContext testContext)
        {
            var builder = new ConfigurationBuilder()
                .AddUserSecrets<ProjectTests>();

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
        public void GetLastScan()
        {
            var scan = astclient.GetLastScan(
                ProjectId,
                false,
                branch: null,
                scanType: ScanTypeEnum.sast,
                maxScanDate: DateTime.Now);

            Assert.IsNotNull(scan);

            Trace.WriteLine(scan.Id);
            Trace.WriteLine(scan.CreatedAt.ToString());

            var result = astclient.GetSASTScanResultsById(scan.Id);

            Assert.IsTrue(result.Any());

            Assert.AreEqual(1964, result.Count());
        }

        private Guid ProjectId = new Guid("1d0d1c07-56d7-40e5-8ffd-21638bfb0f9d");

        [TestMethod]
        public void GetAllScansTest()
        {
            var scans = astclient.GetAllScans(ProjectId);

            Assert.AreEqual(2, scans.Count());

            foreach (var scan in scans)
            {
                Trace.WriteLine($"{scan.Id} {scan.CreatedAt.DateTime.ToLongTimeString()}");
            }

        }

        [TestMethod]
        public void GetFileFormatsTest()
        {
            var results = astclient.Requests.GetFileFormats().Result;

            foreach (var result in results)
            {
                Trace.WriteLine(result.Route);

                foreach (var item in result.FileFormats)
                {
                    Trace.WriteLine($"\t{item}");
                }
            }
        }

        [TestMethod]
        public void RandomMarkingTheSCAFindingsTest()
        {
            ScanReportJson result = astclient.Requests.GetScanReport(
                astclient.GetLastScan(ProjectId, fullScanOnly: false, completed: true, scanType: ScanTypeEnum.sca).Id);

            Assert.IsNotNull(result);

            foreach (var vuln in result.Vulnerabilities)
            {
                astclient.MarkSCAVulnerability(ProjectId, vuln,
                    GetRandomEnumMember<VulnerabilityStatus>(),
                    GetRandomJoke());
            }
        }

        [TestMethod]
        public void RandomMarkingTheSASTFindingsTest()
        {
            var results = astclient.GetSASTScanResultsById(
                astclient.GetLastScan(ProjectId, fullScanOnly: false, completed: true, scanType: ScanTypeEnum.sast).Id);

            Assert.IsNotNull(results);

            foreach (var vuln in results)
            {
                astclient.MarkSASTResult(ProjectId, vuln.SimilarityID,
                    vuln.Severity,
                    GetRandomEnumMember<ResultsState>(),
                    GetRandomJoke());
            }
        }

        [TestMethod]
        public void RandomMarkingTheIaCFindingsTest()
        {
            var results = astclient.GetKicsScanResultsById(
                astclient.GetLastScan(ProjectId, fullScanOnly: false, completed: true, scanType: ScanTypeEnum.kics).Id);

            Assert.IsNotNull(results);

            foreach (var vuln in results)
            {
                astclient.MarkKICSResult(vuln.SimilarityID, ProjectId,
                    vuln.Severity,
                    GetRandomEnumMember<KicsStateEnum>(),
                    GetRandomJoke());
            }
        }

        private static Random random = new Random();
        private static List<string> jokes = new List<string>()
    {
          "Why do programmers prefer dark mode? Because light attracts bugs!",
        "Why don't programmers like nature? Too many bugs.",
        "How many programmers does it take to change a light bulb? None, that's a hardware problem.",
        "I don't see any security issues here. - Said no pen tester ever.",
        "Why do programmers always mix up Halloween and Christmas? Because Oct 31 == Dec 25!",
        "Why was the JavaScript developer sad? Because he didn't Node how to Express himself!",
        "How do you explain the movie Inception to a programmer? It's a function that calls itself!",
        "Why did the security engineer go broke? Because he lost his cache!",
        "A SQL query walks into a bar, walks up to two tables and asks, 'Can I join you?'",
        "Why is it that programmers always confuse Christmas with Halloween? Because 31 OCT equals 25 DEC.",
        "What's the object-oriented way to become wealthy? Inheritance.",
        "How many programmers does it take to kill a cockroach? Two: one holds, the other installs Windows on it.",
        "Why do Java developers wear glasses? Because they don't C#!",
        "On a scale of one to ten, what's your favorite color of the alphabet in the office?",
        "Have you heard about the new Cray super computer? It�s so fast, it executes an infinite loop in 6 seconds.",
        "Why did the developer go broke? Because he used up all his cache.",
        "Why did the geek add body { padding-top: 1000px; } to his Facebook profile? He wanted to keep a low profile.",
        "Why was the developer's family stuck at home on weekends? He was too busy debugging.",
        "Why do Python devs need glasses? Because they can't C.",
        "How do you comfort a JavaScript bug? You console it.",
        "When a JavaScript error and a Python error see each other, what do they say? 'Let's swap some pointers sometime!'",
        "Why don't programmers like to pass their laptop or PC to others? Because they can't handle the session!",
        "How do you stop a web developer stealing? Write 403 on their forehead!",
        "Why was the JavaScript reality show cancelled after only one episode? People thought it was unscripted!",
        "Why did the programmer quit his job? Because he didn't get arrays (a raise).",
        "A programmer puts two glasses on his bedside table before going to sleep. A full one, in case he gets thirsty, and an empty one, in case he doesn�t.",
        "Why do C# and Java developers keep breaking their keyboards? Because they use strong typing.",
        "Why do programmers prefer using dark mode? Because light attracts bugs.",
        "What do you call a group of security guards in front of a Samsung store? Guardians of the Galaxy.",
        "What does a hacker do on a boat? Phishing.",
        "Why did the programmer go to therapy? To resolve his dependency issues.",
        "Why don't fish work on the web? They're scared of the net.",
        "What's a programmer's favorite hangout place? Foo Bar!",
        "What's a bug on the Internet? A feature on spiderweb sites!"
        };

        public static string GetRandomJoke()
        {
            int index = random.Next(jokes.Count);
            return jokes[index];
        }

        public static T GetRandomEnumMember<T>() where T : Enum
        {
            Random random = new Random();
            var values = Enum.GetValues(typeof(T));
            return (T)values.GetValue(random.Next(values.Length));
        }

   

        [TestMethod]
        public void GetListOfStatesTest()
        {
            foreach (var state in astclient.Lists.GetStatesListAsync().Result)
            {
                Trace.WriteLine(state);
            }
        }

        [TestMethod]
        public void GetSCAPackagesJsonReportTest()
        {
            var result = astclient.Requests.GetReportRequest(
                astclient.GetLastScan(ProjectId, fullScanOnly: false, completed: true, scanType: ScanTypeEnum.sca).Id, "SpdxJson");

            Trace.WriteLine(result);

            Assert.IsNotNull(result);
        }


        [TestMethod]
        public void GetSCAReportTest()
        {
            var result = astclient.Requests.GetReportRequest(
                astclient.GetLastScan(ProjectId, fullScanOnly: false, completed: true, scanType: ScanTypeEnum.sca).Id, "CycloneDxJSON");

            Trace.WriteLine(result);

            Assert.IsNotNull(result);
        }


        [TestMethod]
        public void ListSCAFindings()
        {
            astclient.GetProject(ProjectId);

            astclient.GetLastScan(ProjectId);
        }
    }
}
