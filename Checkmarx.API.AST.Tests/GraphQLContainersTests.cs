using Checkmarx.API.AST.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Checkmarx.API.AST.Tests;

/// <summary>
/// Tests of the Containers region of <see cref="GraphQLClient"/>: one against a real tenant (user secrets) and the rest
/// offline, with canned answers.
/// </summary>
[TestClass]
public class GraphQLContainersTests
{
    #region Real tenant (user secrets)

    // A scan of the tenant that ran the Containers engine.
    private static readonly Guid TenantScanId = new Guid("a04a4321-e345-42f1-ab05-0547df43673a");

    private static ASTClient TenantClient()
    {
        var configuration = new ConfigurationBuilder()
            .AddUserSecrets<GraphQLContainersTests>()
            .Build();

        // Without the secrets only this test is skipped; the offline tests below still run
        if (string.IsNullOrEmpty(configuration["API_KEY"]))
            Assert.Inconclusive("No API_KEY in the user secrets of the test project.");

        return new ASTClient(
            new Uri(configuration["ASTServer"]),
            new Uri(configuration["AccessControlServer"]),
            configuration["Tenant"],
            configuration["API_KEY"]);
    }

    /// <summary>
    /// Calls every Containers method of the GraphQL client on a real scan: the images, then for each image its
    /// remediation and layers, and its vulnerable packages with their CVEs.
    /// </summary>
    [TestMethod]
    public async Task GetContainersScanResultsFromTenantTest()
    {
        var graphQL = TenantClient().GraphQLClient;

        // GetContainersImagesAsync
        var images = await graphQL.GetContainersImagesAsync(TenantScanId);

        Trace.WriteLine($"Scan {TenantScanId}: {images.Count} images");
        Assert.IsTrue(images.Count > 0, "The scan has no images; is it a Containers scan?");

        foreach (var image in images)
        {
            Trace.WriteLine($"Image {image.ImageName} ({image.ImageId}) base: {image.BaseImage} severity: {image.Severity} " +
                $"C/H/M/L: {image.Vulnerabilities?.CriticalCount}/{image.Vulnerabilities?.HighCount}/{image.Vulnerabilities?.MediumCount}/{image.Vulnerabilities?.LowCount} " +
                $"status: {image.Status} error: {image.ScanError}");

            // GetContainersImageDetailAsync (remediation + layers)
            var detail = await graphQL.GetContainersImageDetailAsync(TenantScanId, image.ImageId);

            Assert.IsNotNull(detail);
            Trace.WriteLine($"  Remediation: outdated={detail.Remediation?.IsOutdated} " +
                $"minor upgrades={detail.Remediation?.MinorRecommendedImages?.Count} major upgrades={detail.Remediation?.MajorRecommendedImages?.Count}");
            Trace.WriteLine($"  Layers: from images={string.Join(", ", detail.Layers?.FromImages?.Select(x => x.ImageName) ?? Enumerable.Empty<string>())}");

            // GetContainersImageVulnerabilitiesAsync (packages + CVEs)
            var packages = await graphQL.GetContainersImageVulnerabilitiesAsync(TenantScanId, image.ImageId);

            Trace.WriteLine($"  Vulnerable packages: {packages.Count}, CVEs: {packages.Sum(x => x.AggregatedRisks?.RisksList?.Count ?? 0)}");

            foreach (var package in packages.Take(3))
                Trace.WriteLine($"    {package.PackageName} {package.PackageVersion} [{package.MaxRiskSeverity}] status: {package.Status} " +
                    $"CVEs: {string.Join(", ", package.AggregatedRisks?.RisksList?.Take(3).Select(x => x.Cve) ?? Enumerable.Empty<string>())}");
        }
    }

    #endregion

    #region Offline (canned answers)

    private const string ContainersUrl = "https://ast.test/api/containers/buffet/graphql";

    private static readonly Guid ScanId = new Guid("11111111-1111-1111-1111-111111111111");

    private sealed class FakeHandler : HttpMessageHandler
    {
        private readonly Queue<(HttpStatusCode Status, string Body)> _answers = new();

        public List<HttpRequestMessage> Requests { get; } = new();
        public List<JObject> Bodies { get; } = new();

        public FakeHandler Answer(string json, HttpStatusCode status = HttpStatusCode.OK)
        {
            _answers.Enqueue((status, json));
            return this;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request);
            Bodies.Add(JObject.Parse(await request.Content.ReadAsStringAsync().ConfigureAwait(false)));

            var (status, body) = _answers.Dequeue();
            return new HttpResponseMessage(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        }
    }

    private static GraphQLClient Client(FakeHandler handler, string containersUrl = ContainersUrl) =>
        new GraphQLClient(new HttpClient(handler), "https://ast.test/api/sca/graphql/graphql", containersUrl);

    private static string ImagesPage(int total, params string[] imageIds) =>
        new JObject
        {
            ["data"] = new JObject
            {
                ["images"] = new JObject
                {
                    ["totalCount"] = total,
                    ["items"] = new JArray(imageIds.Select(id => new JObject
                    {
                        ["imageId"] = id,
                        ["imageName"] = id + ":latest",
                        ["severity"] = "HIGH",
                        ["fixable"] = true,
                        ["runtime"] = false,
                        ["size"] = 123456789,
                        ["isImageMalicious"] = "Not Malicious",
                        ["snoozeDate"] = null,
                        ["groupsData"] = new JArray(new JObject { ["filePath"] = "/Dockerfile" }),
                        ["vulnerabilities"] = new JObject { ["criticalCount"] = 1, ["highCount"] = 2, ["mediumCount"] = 3, ["lowCount"] = 4, ["noneCount"] = 0 }
                    }))
                }
            }
        }.ToString();

    [TestMethod]
    public async Task GetContainersImages_WalksEveryPageOfTheContainersEndpoint()
    {
        var handler = new FakeHandler().Answer(ImagesPage(3, "a", "b")).Answer(ImagesPage(3, "c"));

        var images = await Client(handler).GetContainersImagesAsync(ScanId, pageSize: 2);

        CollectionAssert.AreEqual(new[] { "a", "b", "c" }, images.Select(x => x.ImageId).ToArray());
        Assert.AreEqual(2, handler.Requests.Count);

        // Always the Containers endpoint, with the Accept header of the UI, never the SCA one
        Assert.IsTrue(handler.Requests.All(x => x.RequestUri.AbsoluteUri == ContainersUrl));
        Assert.IsTrue(handler.Requests.All(x => x.Headers.Accept.ToString() == "application/json; version=1.0"));

        // The scan id, then skip 0 and skip 2 with take 2
        Assert.AreEqual(ScanId.ToString(), (string)handler.Bodies[0]["variables"]["s"]);
        Assert.AreEqual(0, (int)handler.Bodies[0]["variables"]["skip"]);
        Assert.AreEqual(2, (int)handler.Bodies[1]["variables"]["skip"]);
        Assert.AreEqual(2, (int)handler.Bodies[1]["variables"]["take"]);
        Assert.IsNull(handler.Bodies[0]["variables"]["i"]);

        var first = images[0];
        Assert.AreEqual("/Dockerfile", first.GroupsData.Single().FilePath);
        Assert.AreEqual(1, first.Vulnerabilities.CriticalCount);
        Assert.AreEqual(true, first.Fixable);
        Assert.AreEqual(false, first.Runtime);
        Assert.AreEqual(123456789L, first.Size);
        Assert.AreEqual("Not Malicious", first.IsImageMalicious);
        Assert.IsNull(first.SnoozeDate);
    }

    [TestMethod]
    public async Task GetContainersImages_StopsOnAnEmptyPage()
    {
        // totalCount says 5 but the endpoint has nothing more: must not loop forever
        var handler = new FakeHandler().Answer(ImagesPage(5, "a")).Answer(ImagesPage(5));

        var images = await Client(handler).GetContainersImagesAsync(ScanId, pageSize: 1);

        Assert.AreEqual(1, images.Count);
        Assert.AreEqual(2, handler.Requests.Count);
    }

    [TestMethod]
    public async Task GetContainersImageDetail_ReadsRemediationAndLayersInOneCall()
    {
        var handler = new FakeHandler().Answer(@"{ ""data"": {
            ""imageRemediations"": { ""isOutdated"": true, ""distribution"": ""debian"", ""vulnerabilitiesCount"": 40,
                ""minorRecommendedImages"": [ { ""imageId"": ""node:20.1"", ""vulnerabilitiesCount"": 10, ""criticalVulnerabilitiesCount"": 0, ""highVulnerabilitiesCount"": 2 } ],
                ""majorRecommendedImages"": [] },
            ""imageLayers"": { ""fixable"": true, ""fixableImage"": false,
                ""fromImages"": [ { ""imageName"": ""node:18"", ""layers"": [ { ""layerId"": ""sha256:1"" }, { ""layerId"": ""sha256:2"" } ] } ] } } }");

        var detail = await Client(handler).GetContainersImageDetailAsync(ScanId, "img-1");

        Assert.AreEqual(1, handler.Requests.Count);
        Assert.AreEqual("img-1", (string)handler.Bodies[0]["variables"]["i"]);

        Assert.AreEqual(true, detail.Remediation.IsOutdated);
        Assert.AreEqual("node:20.1", detail.Remediation.MinorRecommendedImages.Single().ImageId);
        Assert.AreEqual(0, detail.Remediation.MajorRecommendedImages.Count);
        Assert.AreEqual(false, detail.Layers.FixableImage);
        CollectionAssert.AreEqual(new[] { "sha256:1", "sha256:2" }, detail.Layers.FromImages.Single().Layers.Select(x => x.LayerId).ToArray());
    }

    [TestMethod]
    public async Task GetContainersImageVulnerabilities_ReadsPackagesAndTheirCves()
    {
        var handler = new FakeHandler().Answer(@"{ ""data"": { ""imagesVulnerabilities"": { ""totalCount"": 1, ""items"": [ {
            ""packageId"": ""p1"", ""packageName"": ""openssl"", ""packageVersion"": ""1.1.1"", ""type"": ""deb"", ""maxRiskSeverity"": ""CRITICAL"",
            ""risksCount"": 1, ""status"": ""Monitored"", ""snoozeDate"": null, ""isStatusGlobal"": false,
            ""imageTriageRegexes"": [ ""openssl.*"" ], ""runtimeUsage"": ""InUse"", ""isSource"": false, ""isMalicious"": ""Not Found"",
            ""layerIds"": [ ""sha256:1"" ],
            ""aggregatedRisks"": { ""critical"": 1, ""high"": 0, ""medium"": 0, ""low"": 0, ""none"": 0, ""risksList"": [ {
                ""cve"": ""CVE-2024-0001"", ""cwe"": ""CWE-79"", ""vulnerabilityLevel"": ""CRITICAL"", ""vulnerabilityScore"": 9.8,
                ""originalSeverityLevel"": ""HIGH"", ""originalScore"": 8.1, ""advisoryBaseScore"": ""7.5"", ""cvssVersion"": ""3.1"",
                ""state"": ""TO_VERIFY"", ""customStateId"": null, ""isExploitable"": true, ""fixable"": true, ""fixedVersion"": ""1.1.2"",
                ""publicationDate"": ""2024-03-01T00:00:00Z"",
                ""statusInfo"": { ""status"": ""NEW"", ""firstScanId"": ""abc"", ""firstFoundDate"": ""2024-04-02T10:00:00Z"" } } ] } } ] } } }");

        var packages = await Client(handler).GetContainersImageVulnerabilitiesAsync(ScanId, "img-1");

        Assert.AreEqual("img-1", (string)handler.Bodies[0]["variables"]["i"]);

        var package = packages.Single();
        Assert.AreEqual("openssl", package.PackageName);
        Assert.AreEqual("InUse", package.RuntimeUsage);
        Assert.AreEqual("Not Found", package.IsMalicious);
        CollectionAssert.AreEqual(new[] { "openssl.*" }, package.ImageTriageRegexes);

        var risk = package.AggregatedRisks.RisksList.Single();
        Assert.AreEqual("CVE-2024-0001", risk.Cve);
        Assert.AreEqual(9.8, risk.VulnerabilityScore);
        Assert.AreEqual("7.5", risk.AdvisoryBaseScore);
        Assert.AreEqual(true, risk.IsExploitable);
        Assert.AreEqual("1.1.2", risk.FixedVersion);
        Assert.AreEqual(new DateTime(2024, 4, 2, 10, 0, 0, DateTimeKind.Utc), risk.StatusInfo.FirstFoundDate.Value.ToUniversalTime());
    }

    [TestMethod]
    public async Task GraphQLErrors_AnsweredWithHttp200_AreThrown()
    {
        var handler = new FakeHandler().Answer(@"{ ""errors"": [ { ""message"": ""Cannot query field 'nope'"" } ], ""data"": null }");

        var ex = await Assert.ThrowsExactlyAsync<HttpRequestException>(() => Client(handler).GetContainersImagesAsync(ScanId));

        StringAssert.Contains(ex.Message, "Cannot query field 'nope'");
    }

    [TestMethod]
    public async Task NonSuccessStatus_IsThrownWithTheBody()
    {
        var handler = new FakeHandler().Answer("{ \"detail\": \"forbidden\" }", HttpStatusCode.Forbidden);

        var ex = await Assert.ThrowsExactlyAsync<HttpRequestException>(() => Client(handler).GetContainersImagesAsync(ScanId));

        StringAssert.Contains(ex.Message, "403");
        StringAssert.Contains(ex.Message, "forbidden");
    }

    [TestMethod]
    public void Constructor_RequiresTheClientAndBothEndpoints()
    {
        var http = new HttpClient(new FakeHandler());

        Assert.ThrowsExactly<ArgumentNullException>(() => new GraphQLClient(null, "https://ast.test/sca", ContainersUrl));
        Assert.ThrowsExactly<ArgumentException>(() => new GraphQLClient(http, " ", ContainersUrl));
        Assert.ThrowsExactly<ArgumentException>(() => new GraphQLClient(http, "https://ast.test/sca", null));
        Assert.ThrowsExactly<ArgumentException>(() => new GraphQLClient(http, "https://ast.test/sca", ""));
    }

    [TestMethod]
    public void TheTwoEndpointsAreKeptApart()
    {
        var client = new GraphQLClient(new HttpClient(new FakeHandler()), "https://ast.test/sca", ContainersUrl);

        Assert.AreEqual("https://ast.test/sca/", client.SCABaseUrl);   // the SCA url keeps its trailing slash
        Assert.AreEqual(ContainersUrl, client.ContainersBaseUrl);
    }

    [TestMethod]
    public async Task EmptyScanOrImageId_IsRejectedBeforeAnyCall()
    {
        var handler = new FakeHandler();
        var client = Client(handler);

        await Assert.ThrowsExactlyAsync<ArgumentException>(() => client.GetContainersImagesAsync(Guid.Empty));
        await Assert.ThrowsExactlyAsync<ArgumentException>(() => client.GetContainersImageDetailAsync(ScanId, " "));
        await Assert.ThrowsExactlyAsync<ArgumentException>(() => client.GetContainersImageVulnerabilitiesAsync(ScanId, null));

        Assert.AreEqual(0, handler.Requests.Count);
    }

    #endregion
}
