using Checkmarx.API.AST.Enums;
using Checkmarx.API.AST.Models;
using Checkmarx.API.AST.Services.Configuration;
using Checkmarx.API.AST.Services.SASTResults;
using Checkmarx.API.AST.Services.SASTScanResultsCompare;
using Checkmarx.API.AST.Services.Scans;
using Microsoft.Extensions.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;

namespace Checkmarx.API.AST.Tests
{
    [TestClass]
    public class ScanTests
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
        public async Task GetScanSourceCodeTest()
        {
            Guid scanId = new Guid("e89e5562-1f92-408a-bf96-60fc91aee856");

            var fileResponse = astclient.GetSourceCode(scanId);
        }

        [TestMethod]
        public void FixedResultsTest()
        {
            Guid projectId = new Guid("89cfe246-ea1a-468f-9546-a814c180da01");

            Guid baseScan = new Guid("f2c0dbc6-4e91-4b3e-867e-e5c1add753d8");
            Guid resolveScan = new Guid("f767d726-b743-4b65-8766-f87fbf36926f");

            var compare = astclient.GetSASTScanCompareResultsByScans(baseScan, resolveScan).ToList();
        }

        [TestMethod]
        public void GetScanLegalRiskTest()
        {
            Guid scanId = new Guid("261d7043-8f2c-4e77-bfa4-b37dad7c19ce");

            var legalRisk = astclient.GetSCAScanLegalRisk(scanId);

            Trace.WriteLine($"Scan Legal Risk: {legalRisk.Data.LegalRisksByScanId?.TotalCount}");
        }

        [TestMethod]
        public void GetScanResultsCompareTest()
        {
            Guid baseScanId = new Guid("5431ed22-8456-463f-8da6-3ddedf1ec34b");
            Guid scanId = new Guid("41f28678-a654-4cda-a9ee-6206ab10dde9");

            var compare = astclient.GetScanResultsCompare(baseScanId, scanId);

            // Counters
            var criticalFixedResults = compare.GetResultCountByStatus(StatusEnumCmp.FIXED, SeverityEnum.CRITICAL);
            var highFixedResults = compare.GetResultCountByStatus(StatusEnumCmp.FIXED, SeverityEnum.HIGH);
            var mediumFixedResults = compare.GetResultCountByStatus(StatusEnumCmp.FIXED, SeverityEnum.MEDIUM);
            var lowFixedResults = compare.GetResultCountByStatus(StatusEnumCmp.FIXED, SeverityEnum.MEDIUM);

            var fixedResults = compare.GetResultCountByStatus(StatusEnumCmp.FIXED);
            var newResults = compare.GetResultCountByStatus(StatusEnumCmp.NEW);
            var recurentResults = compare.GetResultCountByStatus(StatusEnumCmp.RECURRENT);

            Trace.WriteLine($"Fixed: {fixedResults} | New: {newResults} | Recurrent: {recurentResults}");
        }

        [TestMethod]
        public void GetScanDetailsTest()
        {
            var projects = astclient.GetAllProjectsDetails();
            var project = projects.Single(
                x => x.Name == "plug-and-sell/JAVA/crosssell-core-pb");

            var lastScan = astclient.GetLastScan(project.Id);

            var automatedScanDetails = astclient.GetScanDetails(lastScan.Id);
        }

        [TestMethod]
        public void LastScanByEngineTest()
        {
            var projects = astclient.GetAllProjectsDetails();

            var project = projects.SingleOrDefault(x => x.Name == "learning-central-admin-center");

            var lastSastScan = astclient.GetLastScan(project.Id, scanType: Enums.ScanTypeEnum.sast);
            if (lastSastScan != null)
            {
                var scanDetails = astclient.GetScanDetails(lastSastScan.Id);
                var sastResults = scanDetails.SASTResults;
                if (sastResults != null)
                {
                    Trace.WriteLine($"Project {project.Name}: SAST Scan Status - {sastResults.Status} | Scan Results - {sastResults.Critical ?? 0} Criticals, {sastResults.High ?? 0} Highs, {sastResults.Medium ?? 0} Mediums, {sastResults.Low ?? 0} Lows");
                }
                else
                {
                    Trace.WriteLine($"Project {project.Name} has no SAST results.");
                }
            }

            var lastScaScan = astclient.GetLastScan(project.Id, scanType: Enums.ScanTypeEnum.sca);
            if (lastScaScan != null)
            {
                var scanDetails = astclient.GetScanDetails(lastScaScan.Id);
                var scaResults = scanDetails.ScaResults;
                if (scaResults != null)
                {
                    Trace.WriteLine($"Project {project.Name}: SCA Scan Status - {scaResults.Status} | Scan Results - {scaResults.Critical ?? 0} Criticals, {scaResults.High ?? 0} Highs, {scaResults.Medium ?? 0} Mediums, {scaResults.Low ?? 0} Lows");
                }
                else
                {
                    Trace.WriteLine($"Project {project.Name} has no SCA results.");
                }
            }

            var lastIacScan = astclient.GetLastScan(project.Id, scanType: Enums.ScanTypeEnum.kics);
            if (lastIacScan != null)
            {
                var scanDetails = astclient.GetScanDetails(lastIacScan.Id);
                var iacResults = scanDetails.KicsResults;
                if (iacResults != null)
                {
                    Trace.WriteLine($"Project {project.Name}: IAC Scan Status - {iacResults.Status} | Scan Results - {iacResults.Critical ?? 0} Criticals, {iacResults.High ?? 0} Highs, {iacResults.Medium ?? 0} Mediums, {iacResults.Low ?? 0} Lows");
                }
                else
                {
                    Trace.WriteLine($"Project {project.Name} has no SCA results.");
                }
            }
        }

        [TestMethod]
        public void DeleteProjectsTest()
        {
            var projects = astclient.GetAllProjectsDetails();

            var projsScanned = projects.Where(x => x.Tags.ContainsKey("sast_id"));

            foreach (var project in projsScanned)
            {
                var lastScan = astclient.GetLastScan(project.Id, scanType: Enums.ScanTypeEnum.sca);
                if (lastScan != null)
                {
                    var scanDetails = astclient.GetScanDetails(lastScan.Id);
                    var scaResults = scanDetails.ScaResults;
                    if (scaResults != null)
                    {
                        Trace.WriteLine($"Prtoject {project.Name}: Scan Status - {scaResults.Status} | Scan Results - {scaResults.High ?? 0} Highs, {scaResults.Medium ?? 0} Mediums, {scaResults.Low ?? 0} Lows");
                    }
                    else
                    {
                        Trace.WriteLine($"Prtoject {project.Name} has no SCA results.");
                    }
                }
                else
                {
                    Trace.WriteLine($"Prtoject {project.Name} has no scan.");
                }
            }
        }

        [TestMethod]
        public void GetScanConfigurationTest()
        {
            var test = astclient.GetProjectConfiguration(new Guid("0c04039e-69f5-41f7-89f5-2e3fd94bd547"));
        }

        [TestMethod]
        public void GetSCAInfoTest()
        {
            var projects = astclient.GetAllProjectsDetails();

            var proj = projects.Where(x => x.Name == "cs_lac_tyt_ws5bfel_util_prod").FirstOrDefault();

            var resultsOverview = astclient.ResultsOverview.ProjectsAsync(new List<Guid>() { proj.Id }).Result;

            var lastSASTScan = astclient.GetLastScan(proj.Id, true, true, scanType: Enums.ScanTypeEnum.sca);

            //var scanners = astclient.GetScanDetailsOLD(new Guid(proj.Id), new Guid(lastSASTScan.Id), DateTime.Now);

            var newScanDetails = astclient.GetScanDetails(lastSASTScan.Id);
        }

        [TestMethod]
        public void GetScanInfoTest()
        {
            var projects = astclient.GetAllProjectsDetails();
            //var proj = projects.Where(x => x.Name == "cs_lac_tyt_ws5bfel_util_prod").FirstOrDefault();

            foreach (var proj in projects)
            {
                //var proj = astclient.Projects.GetProjectAsync(new Guid("fd71de0b-b3db-40a8-a885-8c2d0eb481b6")).Result;
                //var scansList = astclient.GetScans(new Guid(proj.Id)).ToList();
                var lastSASTScan = astclient.GetLastScan(proj.Id, true);
                if (lastSASTScan == null)
                    continue;

                var newScanDetails = astclient.GetScanDetails(lastSASTScan.Id);

                if (newScanDetails.SASTResults == null)
                    continue;

                Trace.WriteLine($"Total: {newScanDetails.SASTResults?.Total} | High: {newScanDetails.SASTResults?.High} | Medium: {newScanDetails.SASTResults?.Medium} | Low: {newScanDetails.SASTResults?.Low} | Info: {newScanDetails.SASTResults?.Info} | ToVerify: {newScanDetails.SASTResults?.ToVerify}");
            }
        }

        [TestMethod]
        public void GetScanResultsTest()
        {
            var proj = astclient.Projects.GetProjectAsync(new Guid("723b770a-b9e9-436b-ad66-29326eb6da29")).Result;
            var lastSASTScan = astclient.GetLastScan(proj.Id, true);

            //var newScanDetails = astclient.ScannersResults.GetResultsByScanAsync(new Guid(lastSASTScan.Id)).Result;
            var newScanDetails2 = astclient.GetSASTScanResultsById(lastSASTScan.Id).ToList();
        }

        Guid _projectId = new Guid("3fb4c42c-88ab-4be4-9f15-7ffa88908040");

        [TestMethod]
        public void ListScansTest()
        {
            Assert.IsNotNull(astclient.Scans);

            var projects = astclient.GetAllProjectsDetails();

            foreach (var project in projects)
            {
                foreach (var scan in astclient.GetAllScans(project.Id))
                {
                    Trace.WriteLine($"Project: {project.Name} | " +
                        $"Scan ID: {scan.Id} | " +
                        $"Branch: {scan.Branch} | " +
                        $"Created At: {scan.CreatedAt.DateTime} " +
                        $"| Status: {scan.Status}");
                }
            }
        }


        [TestMethod]
        public void GetLastScanForKicsTest()
        {
            var proj = astclient.Projects.GetProjectAsync(_projectId).Result;

            Scan lastKicsScan = astclient.GetLastScan(proj.Id, true, scanType: Enums.ScanTypeEnum.kics);

            Assert.AreEqual(lastKicsScan.Id, new Guid("96f11e3b-dd7f-4dcc-8d54-e547e0cd8603"));
        }


        [TestMethod]
        public void ListKicsScanResultsTest()
        {
            var proj = astclient.Projects.GetProjectAsync(_projectId).Result;

            Scan lastKicsScan = astclient.GetLastScan(proj.Id, true, scanType: Enums.ScanTypeEnum.kics);

            Trace.WriteLine(lastKicsScan.Id);

            Assert.AreEqual(lastKicsScan.Id, new Guid("96f11e3b-dd7f-4dcc-8d54-e547e0cd8603"));

            var properties = typeof(Services.KicsResults.KicsResult).GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.GetProperty);

            // Fields
            Trace.WriteLine(string.Join(";", properties.Select(p => "\"" + p.Name + "\"")));

            var listOfIaCResults = astclient.GetKicsScanResultsById(lastKicsScan.Id);

            Trace.WriteLine(listOfIaCResults.Count());

            //foreach (Services.KicsResults.KicsResult kicsResult in listOfIaCResults)
            //{
            //    foreach (var property in properties)
            //    {
            //        Trace.WriteLine($"{property.Name} = {property.GetValue(kicsResult)?.ToString()}");
            //    }
            //    Trace.WriteLine("---");
            //}
        }

        [TestMethod]
        public void ListSCAScanResultsTest()
        {
            var proj = astclient.Projects.GetProjectAsync(
                new Guid("80fe1c50-f062-4061-a7ef-576fea9c2971")).Result;

            Scan lastSCAScan = astclient.GetLastScan(proj.Id, true, scanType: Enums.ScanTypeEnum.sca);

            Trace.WriteLine(lastSCAScan.Id);

            Assert.IsNotNull(lastSCAScan);

            var properties = typeof(Services.ScannersResults.ScannerResult).GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.GetProperty);

            var results = astclient.GetScannersResultsById(lastSCAScan.Id, ASTClient.SCA_Engine, ASTClient.SCA_Container_Engine);

            foreach (Services.ScannersResults.ScannerResult result in results)
            {
                foreach (var property in properties)
                {
                    Trace.WriteLine($"{property.Name} = {property.GetValue(result)?.ToString()}");
                }

                Trace.WriteLine("- ADDITIONAL --");

                foreach (var property in result.AdditionalProperties)
                {
                    Trace.WriteLine($"\t{property.Key} = {property.Value}");
                }

                Trace.WriteLine("---");
            }
        }

        [TestMethod]
        public void ListSASTScanTest()
        {
            Assert.IsNotNull(astclient);

            var proj = astclient.Projects.GetProjectAsync(new Guid("049b1439-34b1-498b-bae1-c767652fcbc0")).Result;

            var lastSASTScan = astclient.GetLastScan(proj.Id, true, scanType: Enums.ScanTypeEnum.sast);

            Assert.IsNotNull(lastSASTScan);
        }


        [TestMethod]
        public void ListScansRefactoringTest()
        {
            Assert.IsNotNull(astclient.Scans);

            //var oldScanDetails = astclient.GetScanDetails(new Guid("f8a2b16b-0044-440b-85ed-474bd5d93fca"), new Guid("5963b856-d815-4b8d-990c-1f1eda9e01fe"), DateTime.Now);
            var newScanDetails = astclient.GetScanDetails(new Guid("5963b856-d815-4b8d-990c-1f1eda9e01fe"));

        }

        [TestMethod]
        public void ScanInfoTest()
        {
            var scanID = new Guid("e95da363-b7d9-48e5-9df4-662d76193312");

            var lastScan = astclient.Scans.GetScanAsync(scanID).Result;

            string log = astclient.GetScanLog(lastScan.Id, ASTClient.SAST_Engine);

            var duration = (lastScan.UpdatedAt.DateTime - lastScan.CreatedAt.DateTime);

            Trace.WriteLine("Duration of the Total Scan (seconds): " + duration.Minutes + ":" + duration.Seconds);

            var scanProperties = typeof(Scan).GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.GetProperty);

            Trace.WriteLine(string.Join(";", scanProperties.Select(x => "\"" + x.Name + "\"")));


            foreach (var property in scanProperties)
            {
                if (property.Name == "AdditionalProperties")
                    continue;

                Trace.WriteLine($"{property.Name} = {property.GetValue(lastScan)?.ToString()}");
            }

            Trace.WriteLine("Status Details: ");

            foreach (var status in lastScan.StatusDetails)
            {
                foreach (var property in typeof(Services.Scans.StatusDetails).GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.GetProperty))
                {
                    Trace.WriteLine($"\t+ {property.Name} = {property.GetValue(status)?.ToString()}");
                }
            }

            Trace.WriteLine("Metadata: ");

            foreach (var property in typeof(Services.Scans.Metadata).GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.GetProperty))
            {
                if (property.Name == "AdditionalProperties")
                    continue;

                Trace.WriteLine($"\t+ {property.Name} = {property.GetValue(lastScan.Metadata)?.ToString()}");
            }

            Trace.WriteLine("Metadata.Configs: ");

            foreach (var property in lastScan.Metadata.Configs)
            {
                Trace.WriteLine($"\t+ {property.Type} = {property.Value?.Incremental}");
            }

            Trace.WriteLine("---");


            Trace.WriteLine("WorkflowAsync: ");

            var properties = typeof(TaskInfo).GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.GetProperty);

            Trace.WriteLine(string.Join(";", properties.Select(x => $"\"{x.Name}\"")));

            foreach (TaskInfo item in astclient.Scans.WorkflowAsync(scanID).Result)
            {
                foreach (var property in properties)
                {
                    if (property.Name == "AdditionalProperties")
                        continue;

                    Trace.WriteLine($"{property.Name} = {property.GetValue(item)?.ToString()}");
                }

                foreach (var keyValuePair in item.AdditionalProperties)
                {
                    Trace.WriteLine($"\t + {keyValuePair.Key} = {keyValuePair.Value}");
                }

                Trace.WriteLine("---");
            }

            Trace.WriteLine($"Scan Configurations: Project {lastScan.ProjectId} Scan {lastScan.Id}");

            foreach (var scanConfiguration in astclient.GetScanConfigurations(lastScan.ProjectId, lastScan.Id))
            {
                Trace.WriteLine($"\t + {scanConfiguration.Key}");

                foreach (var property in typeof(ScanParameter).GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.GetProperty))
                {
                    Trace.WriteLine($"\t\t- {property.Name} = {property.GetValue(scanConfiguration.Value)?.ToString()}");
                }
            }

            var teste = astclient.GetScanDetails(lastScan.Id);

            Trace.WriteLine("ScanDetails: ");

            foreach (var property in typeof(ScanDetails).GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.GetProperty))
            {
                Trace.WriteLine($"\t+ {property.Name} = {property.GetValue(teste)?.ToString()}");
            }

            Assert.IsTrue(teste.LoC > 0);
        }

        [TestMethod]
        public void ScanMetadataTest()
        {
            var teste = astclient.SASTMetadata.GetMetadataAsync(new Guid("b0e11442-2694-4102-ae4f-e3a3dcb3559e")).Result;
        }

        [TestMethod]
        public void ScanMetricsTest()
        {
            var project = astclient.GetAllProjectsDetails().Single(x => x.Name == "Teste Thibaud");

            Trace.WriteLine(string.Join(";", astclient.GetScans(project.Id, ASTClient.SAST_Engine).Select(x => x.Id)));

            foreach (var scan in astclient.GetScans(project.Id))
            {
                var scanDetails = astclient.GetScanDetails(scan);

                Trace.WriteLine(scanDetails.Languages);
            }


            // var teste = astclient.SASTMetadata.MetricsAsync(new Guid("b0e11442-2694-4102-ae4f-e3a3dcb3559e")).Result;
        }

        [TestMethod]
        public void FullMetadataTest()
        {
            List<Tuple<Guid, Guid, string, int?, string>> result = new List<Tuple<Guid, Guid, string, int?, string>>();

            var projectList = astclient.Projects.GetListOfProjectsAsync().Result;
            foreach (var project in projectList.Projects)
            {
                var scan = astclient.GetLastScan(project.Id);
                if (scan == null)
                {
                    result.Add(new Tuple<Guid, Guid, string, int?, string>(project.Id, Guid.Empty, project.Name, 0, "No completed scans found"));
                    continue;
                }

                try
                {
                    var scanMetadata = astclient.SASTMetadata.GetMetadataAsync(scan.Id).Result;
                }
                //catch (ApiException apiEx)
                //{
                //    result.Add(new Tuple<Guid, Guid, string, int?, string>(new Guid(project.Id), new Guid(scan.Id), project.Name, apiEx.StatusCode, apiEx.Message));
                //}
                catch (Exception ex)
                {
                    result.Add(new Tuple<Guid, Guid, string, int?, string>(project.Id, scan.Id, project.Name, 0, ex.Message));
                }
            }

            foreach (var item in result)
            {
                Console.WriteLine($"Project Id: {item.Item1} | Scan Id: {item.Item2} | Project Name: {item.Item3} | Status Code: {item.Item4} | Message: {item.Item5}");
            }
        }

        [TestMethod]
        public void FullScanDetailsTest()
        {
            List<Tuple<Guid, Guid, string, int?, string>> result = new List<Tuple<Guid, Guid, string, int?, string>>();

            var projectList = astclient.Projects.GetListOfProjectsAsync().Result;
            foreach (var project in projectList.Projects)
            {
                var scan = astclient.GetLastScan(project.Id);
                if (scan == null)
                {
                    result.Add(new Tuple<Guid, Guid, string, int?, string>(project.Id, Guid.Empty, project.Name, 0, "No completed scans found"));
                    continue;
                }

                try
                {
                    var scanDetails = astclient.GetScanDetails(scan.Id);
                }
                catch (Exception ex)
                {
                    result.Add(new Tuple<Guid, Guid, string, int?, string>(project.Id, scan.Id, project.Name, 0, ex.Message));
                }
            }

            foreach (var item in result)
            {
                Console.WriteLine($"Project Id: {item.Item1} | Scan Id: {item.Item2} | Project Name: {item.Item3} | Status Code: {item.Item4} | Message: {item.Item5}");
            }
        }


        [TestMethod]
        public void ListAllSASTScanTimesTest()
        {

            foreach (var project in astclient.GetAllProjectsDetails())
            {
                foreach (var branch in astclient.GetProjectBranches(project.Id))
                {
                    var lastSASTScan = astclient.GetLastScan(project.Id, false, true, branch, Enums.ScanTypeEnum.sast);
                    if (lastSASTScan != null)
                    {
                        var sastStatus = lastSASTScan.StatusDetails.Single(x => x.Name == Enums.ScanTypeEnum.sast.ToString());
                        Trace.WriteLine($"{project.Name} :: {branch} - LoC {sastStatus.Loc}   |   Duration(s) : {sastStatus.Duration.TotalSeconds}");
                    }
                }
            }
        }

        [TestMethod]
        public void SASTResultsTest()
        {
            var teste = astclient.GetSASTScanResultsById(new Guid("b0e11442-2694-4102-ae4f-e3a3dcb3559e"));
        }

        #region ReRun Scans


        [TestMethod]
        public void GetScanLogsTest()
        {
            string log = astclient.GetScanLog(new Guid("dfb72c6a-ed37-40de-ad25-a75fa4694cd1"), ASTClient.SAST_Engine);

            Assert.IsNotNull(log);
        }

        [TestMethod]
        public void GetSASTEngineLanguageModeTest()
        {
            Trace.WriteLine(astclient.GetSASTEngineLanguageMode(new Guid("dfb72c6a-ed37-40de-ad25-a75fa4694cd1")));
        }

        [TestMethod]
        public void GetWorkFlowTest()
        {
            Trace.WriteLine("WorkflowAsync: ");

            var properties = typeof(TaskInfo).GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.GetProperty);

            Trace.WriteLine(string.Join(";", properties.Select(x => $"\"{x.Name}\"")));

            foreach (TaskInfo item in astclient.Scans.WorkflowAsync(new Guid("537c5a1c-44c8-41f8-8111-28dbe0dc6a0c")).Result)
            {
                foreach (var property in properties)
                {
                    if (property.Name == "AdditionalProperties")
                        continue;

                    Trace.WriteLine($"{property.Name} = {property.GetValue(item)?.ToString()}");
                }

                foreach (var keyValuePair in item.AdditionalProperties)
                {
                    Trace.WriteLine($"\t + {keyValuePair.Key} = {keyValuePair.Value}");
                }

                Trace.WriteLine("---");
            }
        }

        [TestMethod]
        public void WorkFlowQueueTimeTest()
        {
            Trace.WriteLine("WorkflowAsync: ");

            //foreach (var project in astclient.GetAllProjectsDetails())
            //{
            foreach (var scan in astclient.GetScans(new Guid("905bbcd2-8d40-416b-b237-0bbb99201c65")))
            {
                var tasks = astclient.Scans.WorkflowAsync(scan.Id).Result;

                var scanStartedAt = tasks.Single(x => x.Info == "Scan Running").Timestamp;
                // var scanCreatedAt = tasks.Single(x => x.Info == "Scan created").Timestamp;

                // Assert.IsTrue(scanCreatedAt.CompareTo(scan.CreatedAt) == 0);

                Trace.WriteLine($"{scan.Id} - Queue Time: {(scanStartedAt - scan.CreatedAt).TotalSeconds}s");
                //}
            }
        }



        [TestMethod]
        public void ReRunScanGitTest()
        {
            var gitProj = astclient.Projects.GetProjectAsync(new Guid("4bceceba-3be8-4ef6-b822-c7fee658fbf8")).Result;

            var gitProjLastScan = astclient.GetLastScan(gitProj.Id, true);

            var gitProjScanDetails = astclient.GetScanDetails(gitProjLastScan.Id);

            var gitReScanResult = astclient.ReRunGitScan(
                                            gitProj.Id,
                                            gitProjScanDetails.RepoUrl,
                                            new ConfigType[] { ConfigType.Sast },
                                            "master",
                                            "ASA Premium",
                                            enableFastScan: true,
                                            tags: new Dictionary<string, string> { { "Test", null } });

            Trace.WriteLine(gitReScanResult.Id);
        }

        [TestMethod]
        public void ReRunScanZipTest()
        {
            var scan = astclient.Scans.GetScanAsync(new Guid("1e50230f-232b-4717-b496-724119883d8e")).Result;

            var uploadProjScanDetails = astclient.GetScanDetails(scan);

            string uploadProjBranch = uploadProjScanDetails.Branch;

            var uploadReScanResult = astclient.ReRunUploadScan(scan.ProjectId, scan.Id, [ConfigType.Sast], uploadProjBranch, uploadProjScanDetails.Preset, enableFastScan: false);
        }

        [TestMethod]
        public void GetFastScanConfigurationValueTest()
        {
            var scan = astclient.Scans.GetScanAsync(new Guid("ed2ad5ac-0aa4-494b-8a95-ef7b27505099")).Result;

            var scanConfigs = astclient.GetScanDetails(scan);

            Assert.IsTrue(scanConfigs.FastConfigurationEnabled);

        }


        [TestMethod]
        public void GetAllScanTriggerByMeTest()
        {
            var search = astclient.SearchScans("cxservice_pedro.portilha@checkmarx.com", "perfomance_test", ["ASAProgramTracker"]);

            Trace.WriteLine(string.Join(";", search.Select(x => x.Id)));

            foreach (var item in search)
            {
                Trace.WriteLine(item.Id + " " + item.Branch + " " + item.CreatedAt.DateTime.ToString());

                var previousScan = astclient.GetLastScan(item.ProjectId, branch: item.Branch, completed: true, maxScanDate: item.CreatedAt.DateTime.Add(TimeSpan.FromSeconds(-1)));

                Assert.AreNotEqual(item.Id, previousScan.Id);
            }

            Assert.AreEqual(77, search.Count());
        }


        [TestMethod]
        public void GetScanState()
        {
            var scan = astclient.Scans.GetScanAsync(new Guid("422597dc-90fd-44de-bbd4-058a8335727b")).Result;

            Trace.WriteLine(astclient.GetScanDetails(scan).GetTimeDurationPerEngine(ScanTypeEnum.sast).TotalSeconds);
        }


        [TestMethod]
        public void GetLastFullScanTest()
        {
            var scan = astclient.GetLastScan(new Guid("d0800124-64ba-4ed6-b9b2-9b91f925f761"), true, true, branch: "develop", scanType: ScanTypeEnum.sast, DateTime.Parse("2024-05-14T17:47:27.112387Z"));

            Trace.WriteLine(astclient.GetScanDetails(scan).IsIncremental);
        }


        [TestMethod]
        public void ListScanParametersTest()
        {

            Guid scanId = new Guid("f2b86b8e-59ee-4f14-a56a-8892b42bc862");

            var scanDetails = astclient.GetScanDetails(astclient.Scans.GetScanAsync(scanId).Result);

            foreach (var conf in scanDetails.ScanConfigurations)
            {
                Trace.WriteLine(conf.Key + "=" + conf.Value?.Value);
            }

        }


        [TestMethod]
        public void ScanParametersCompareTest()
        {
            Guid previousScanId = new Guid("c8b49478-f580-4ecb-9277-0a97fb71ab3c");
            Guid lastScanId = new Guid("2428f0b6-286a-445e-a7f9-6954fe0ef4a7");

            var previousScanDetails = astclient.GetScanDetails(astclient.Scans.GetScanAsync(previousScanId).Result);
            var lastScanDetails = astclient.GetScanDetails(astclient.Scans.GetScanAsync(lastScanId).Result);

            foreach (var configKey in previousScanDetails.ScanConfigurations.Keys)
            {
                var previousValue = previousScanDetails.ScanConfigurations[configKey].Value;
                var lastValue = lastScanDetails.ScanConfigurations[configKey].Value;

                if (string.Compare(previousValue, lastValue, true) != 0)
                {
                    Trace.WriteLine($"Key {configKey} = Left: \"{previousValue}\" | Right: \"{lastValue}\"");
                }
            }
        }

        [TestMethod]
        public void GetLanguagesTest()
        {
            var scan = astclient.Scans.GetScanAsync(new Guid("7912dbc0-e01c-42ae-868c-95006f0dd3c0")).Result;

            var details = astclient.GetScanDetails(scan);

            Trace.WriteLine(details.Languages);

            Trace.WriteLine("Summary");

            var summary = astclient.ResultsSummary.SummaryByScansIdsAsync([scan.Id]).Result;

            foreach (var item in summary.ScansSummaries.Single().SastCounters.LanguageCounters.Select(x => x.Language))
            {
                Trace.WriteLine(item);
            }
        }


        [TestMethod]
        public void GetLastScanTest()
        {
            var projectID = new Guid("7dfa5653-79d6-490f-8369-99dae0429834");

            var result = astclient.GetLastScan(projectID, true);

            Assert.IsNotNull(result);

            foreach (var item in astclient.GetScans(projectID, branch: "master", engine: ASTClient.SAST_Engine))
            {
                var scanInfo = astclient.GetSASTScanInfo(item.Id);

                var isincmrenetal = astclient.IsScanIncremental(item.Id);

                Trace.WriteLine(item.Id + "::" + isincmrenetal + " -> " + (scanInfo != null ? scanInfo.IncrementalCancelReason : string.Empty));
            }
        }

        [TestMethod]
        public void GetMainBranchTest()
        {
            var project = astclient.GetProject(new Guid("2b63f9cc-448f-48a9-a4f8-9367f3ae9fba"));

            foreach (var item in astclient.GetScans(project.Id, ASTClient.SAST_Engine))
            {
                var result = astclient.GetScanDetails(item);

                Trace.WriteLine($"{result.Id} - {result.LoC} - {result.SASTVulnerabilities.Count()}");
            }
        }


        [TestMethod]
        public void GetScanCompareResultTest()
        {
            var results = astclient.GetSASTScanCompareResultsByScans(new Guid("5c28fc2c-41af-47c6-a338-3f5ec777baba"), new Guid("a957a8f4-8e10-4a82-8df1-b4a5ed8d8935"));

            var properties = typeof(SastResultCompare).GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.GetProperty);

            foreach (var scanCompare in results)
            {
                foreach (var property in properties)
                {
                    Trace.WriteLine($"{property.Name} = {property.GetValue(scanCompare)?.ToString()}");
                }

                Trace.WriteLine("--------------------");
            }
        }


        [TestMethod]
        public void GetProjectByNameTest()
        {
            var project = astclient.GetAllProjectsDetails().Single(x => x.Name == "");

            Assert.AreEqual(project.MainBranch, "master");
        }

        #endregion

        [TestMethod]
        public void GetScanTagsTest()
        {
            Guid scanID = new Guid("59fc65d3-9fda-4cda-af5f-3869484a25ef");

            //astclient.Scans.UpdateTagsAsync(scanID, 
            //    new ModifyScanTagsInput
            //    {
            //        Tags = new Dictionary<string, string> { 
            //            { "Test", "Value" },
            //            { "EmtpyValue", string.Empty },
            //            { "Test2", "" }
            //        }
            //    }).Wait();

            var result = astclient.Scans.GetTagsAsync(scanID).Result.Tags;

            Assert.IsNotNull(result);

            foreach (var item in result)
            {
                Trace.WriteLine($"{item.Key} = {item.Value}");
            }
        }


        [TestMethod]
        public void DeleteScanTest()
        {

            //Guid[] scanIds = new Guid[] {
            //    new Guid("f2b86b8e-59ee-4f14-a56a-8892b42bc862"),
            //    new Guid("c8b49478-f580-4ecb-9277-0a97fb71ab3c"),
            //    new Guid("2428f0b6-286a-445e-a7f9-6954fe0ef4a7")
            //};


            //foreach (var scanId in scanIds)
            //{
            //    astclient.Scans.DeleteScanAsync(scanId).Wait();
            //}


            foreach (var item in astclient.Scans.GetListOfScansAsync(source_origins: ["recalc", "Recalc"]).Result.Scans)
            {
                Trace.WriteLine(item.Id + " " + item.CreatedAt.DateTime.ToShortDateString());

                // astclient.Scans.DeleteScanAsync(item.Id).Wait();
            }


        }


    }
}
