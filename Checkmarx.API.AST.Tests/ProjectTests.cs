using Checkmarx.API.AST.Models;
using Checkmarx.API.AST.Models.Report;
using Checkmarx.API.AST.Services;
using Checkmarx.API.AST.Services.Applications;
using Checkmarx.API.AST.Services.Configuration;
using Checkmarx.API.AST.Services.Reports;
using Checkmarx.API.AST.Services.SASTMetadata;
using Checkmarx.API.AST.Services.Scans;
using Microsoft.Extensions.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Dynamic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Xml.Xsl;

namespace Checkmarx.API.AST.Tests
{
    [TestClass]
    public class ProjectTests
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
        public void ConnectTest()
        {
            Assert.IsTrue(astclient.Connected);
        }

        [TestMethod]
        public void GetPresetsTest()
        {
            var presets = astclient.GetAllPresets();

            foreach (var preset in presets)
            {
                Trace.WriteLine($"{preset.Name} {preset.Custom} {preset.Description}");
            }
        }

        [TestMethod]
        public void OverridePresetTest()
        {
            var presets = astclient.GetAllPresetsDetails();

            var originalPreset = presets.Single(x => x.Name == "Base Preset");
            var targetPreset = presets.Single(x => x.Name == "ASA-Mobile-Express22");

            Assert.IsNotNull(originalPreset);
            Assert.IsNotNull(targetPreset);

            astclient.PresetManagement.UpdatePresetAsync(Scanner.Sast, Convert.ToInt32(targetPreset.Id), new WritePreset
            {
                Name = targetPreset.Name,
                Description = originalPreset.Description?.Substring(0, 60),
                QueriesByFamily = originalPreset.QueriesByFamily // Example query ID
            }).Wait();
        }


        [TestMethod]
        public void ComparePresetTest()
        {
            var presets = astclient.GetAllPresetsDetails();

            var originalPreset = presets.Single(x => x.Name == "Base Preset");
            var targetPreset = presets.Single(x => x.Name == "ASA-Mobile-Express22");

            Assert.IsTrue(PresetManagement.PresetContainsTheSameQueries(originalPreset, targetPreset));
        }

        [TestMethod]
        public void DuplicatePresetTest()
        {
            var presets = astclient.GetAllPresetsDetails();

            foreach (var preset in presets.Where(x => x.Name == "Base Preset"))
            {
                Trace.WriteLine($"{preset.Name} {preset.Custom} {preset.Description}");

                var name = preset.Name + "2";

                if (!presets.Any(x => x.Name == name))
                {
                    astclient.PresetManagement.CreatePresetAsync(Scanner.Sast, new WritePreset
                    {
                        Name = name,
                        Description = preset.Description?.Substring(0, 60),
                        QueriesByFamily = preset.QueriesByFamily
                    }).Wait();
                    break;
                }

            }
        }

        [TestMethod]
        public void GetProjectConfigurationTest()
        {
            string presetName = "scan.config.sast.presetName";

            var projects = astclient.GetAllProjectsDetails();

            Trace.WriteLine(projects.Count());

            foreach (var project in projects)
            {
                var presetConfiguration = astclient.GetProjectConfigurations(project.Id)[presetName];

                Trace.WriteLine(project.Name + ";" + presetConfiguration.Value + ";" + presetConfiguration.OriginLevel);
            }
        }

        [TestMethod]
        public void ProjectAndScanTest()
        {
            Guid projectId = new Guid("2c5f30fd-c02f-4fa9-9a3c-816ade9d0cb4");

            var lastScan = astclient.GetLastScan(projectId, branch: "master");
            if (lastScan == null)
            {
                return;
            }

            var project = astclient.Projects.GetProjectAsync(projectId).Result;

            //var scanPreset = astclient.GetScanPresetFromConfigurations(projectId, new Guid(lastScan.Id));

            //var scanDetails = astclient.GetScanDetails(projectId, new Guid(lastScan.Id));

            Stopwatch stopwatch = Stopwatch.StartNew();

            var scanResults = astclient.GetSASTScanResultsById(lastScan.Id).ToList();

            Trace.WriteLine(stopwatch.Elapsed.TotalSeconds);

            if (scanResults.Any())
            {
                foreach (var resultByQuery in scanResults.GroupBy(x => x.QueryID))
                {
                    foreach (var result in resultByQuery)
                    {
                        var record = new ExpandoObject() as IDictionary<string, object>;

                        record.Add("ProjectId", project.Id);
                        record.Add("ProjectName", project.Name);
                    }
                }

            }
        }

        [TestMethod]
        public void CreateAndScanNewProjectTest()
        {
            try
            {
                //bool createApp = true;
                //string appId = null;

                //if (createApp)
                //{
                //    var apps = astclient.GetAllApplications();
                //    appId = apps.Applications.Where(x => x.Name == "TestApp").FirstOrDefault()?.Id;

                //    if (appId == null)
                //    {
                //        try
                //        {
                //            var newApp = astclient.Applications.CreateApplicationAsync(new ApplicationInput { Name = "TestApp" }).Result;
                //            appId = newApp.Id;
                //        }
                //        catch (Exception ex)
                //        {
                //            Trace.WriteLine(ex.Message);
                //        }
                //    }
                //}

                Dictionary<string, string> tags = new Dictionary<string, string>();
                tags.Add("sast_id", "1111");

                var createdProject = astclient.CreateProject("API Created Project", tags);

                byte[] data = File.ReadAllBytes("D:\\path_to_file\\csharp.zip");

                string branch = null;
                string preset = null;
                string configuration = null;

                astclient.RunUploadScan(createdProject.Id, data, new List<ConfigType>() { ConfigType.Sca }, branch, preset, configuration);
            }
            catch (Exception ex)
            {
                Trace.WriteLine(ex.Message);
            }
        }

        [TestMethod]
        public void ListProjects()
        {
            Assert.IsNotNull(astclient.Projects);

            var projectsList = astclient.GetAllProjectsDetails();

            foreach (var item in projectsList)
            {
                Trace.WriteLine(item.Name);
            }


            // Assert.AreEqual(221, projectsList.Count);

            //foreach (var proj in projectsList)
            //{
            //    var branches = astclient.GetProjectBranches(proj.Id).ToList();

            //    Assert.IsNotNull(branches, proj.Name);
            //    Assert.IsTrue(branches.Any(), proj.Name);
            //}
        }

        [TestMethod]
        public void GroupsTest()
        {
            Assert.IsNotNull(astclient);

            foreach (var item in astclient.AccessManagement.GetGroupsAsync(1000, 0, null, null).Result)
            {
                Trace.WriteLine(item.Id + " -> " + item.Name);
            }
        }

        [TestMethod]
        public void ProjectApplicationTest()
        {
            Assert.IsNotNull(astclient.Applications);

            var projects = astclient.GetAllProjectsDetails();

            Trace.WriteLine(projects.Count);

        }

        [TestMethod]
        public void ListApplications()
        {
            Assert.IsNotNull(astclient.Applications);

            var applicationsList = astclient.Applications.GetListOfApplicationsAsync().Result;

            foreach (var item in applicationsList.Applications)
            {
                Trace.WriteLine(item.Id + " " + item.Name);
            }
        }

        [TestMethod]
        public void BranchesTest()
        {
            Guid projectId = new Guid("155b3c81-5b85-4bdc-9eb2-e69062f6fc7d");

            Assert.IsNotNull(astclient.Projects);
            Assert.IsNotNull(astclient.Projects.GetProjectAsync(projectId).Result);

            var branchesV2 = astclient.GetProjectBranches(projectId).ToList();

            foreach (var item in branchesV2)
                Trace.WriteLine(item);

            Assert.IsNotNull(branchesV2);
            Assert.IsTrue(branchesV2.Count > 0);
        }

        [TestMethod]
        public void SASTResultsTest()
        {
            var teste = astclient.GetSASTScanResultsById(new Guid("b0e11442-2694-4102-ae4f-e3a3dcb3559e"));
        }

        [TestMethod]
        public void GetAndAPISecuritySwaggerFolderFileFilterTest()
        {
            Guid projectId = new Guid("441b55e8-225b-47f0-83b5-5b1f82e9d343");

            var projeSetting = astclient.GetProjectAPISecuritySwaggerFolderFileFilter(projectId);

            astclient.DeleteProjectConfiguration(projectId, "scan.config.apisec.swaggerFilter");

            var setting2 = astclient.GetProjectAPISecuritySwaggerFolderFileFilter(projectId);
        }

        [TestMethod]
        public void GetExclusionsTest()
        {
            Guid projectId = new Guid("155b3c81-5b85-4bdc-9eb2-e69062f6fc7d");

            var test = astclient.GetProjectFilesAndFoldersExclusions(projectId);
        }

        [TestMethod]
        public void SetExclusionsTest()
        {
            Guid projectId = new Guid("155b3c81-5b85-4bdc-9eb2-e69062f6fc7d");

            astclient.SetProjectExclusions(projectId, ".zip,.gz");
        }

        [TestMethod]
        public void ClearConfigTest()
        {
            astclient.SetProjectConfig(new Guid("4bceceba-3be8-4ef6-b822-c7fee658fbf8"), ASTClient.FastScanConfiguration, null);
        }
    }
}
