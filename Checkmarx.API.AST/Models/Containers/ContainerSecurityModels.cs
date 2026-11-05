using Newtonsoft.Json;
using System;
using System.Collections.Generic;

namespace Checkmarx.API.AST.Models.Containers
{
    // Models of the Container Security GraphQL API (POST /api/containers/buffet/graphql), the one the
    // Checkmarx One results page uses. The field names and types come from the queries in GraphQLClient
    // (region "Containers"); every property that can be missing for a scan is nullable.

    #region Envelope

    /// <summary>GraphQL answer: the data of the query, or the errors (HTTP 200 is returned for both).</summary>
    public class ContainersGraphQLResponse<TData>
    {
        [JsonProperty("data")]
        public TData Data { get; set; }

        [JsonProperty("errors")]
        public List<ContainersGraphQLError> Errors { get; set; }
    }

    public class ContainersGraphQLError
    {
        [JsonProperty("message")]
        public string Message { get; set; }
    }

    /// <summary>One page of a paged field (skip/take).</summary>
    public class ContainersPage<TItem>
    {
        [JsonProperty("totalCount")]
        public int TotalCount { get; set; }

        [JsonProperty("items")]
        public List<TItem> Items { get; set; }
    }

    public class ContainersImagesData
    {
        [JsonProperty("images")]
        public ContainersPage<ContainersImage> Images { get; set; }
    }

    public class ContainersImageDetailData
    {
        [JsonProperty("imageRemediations")]
        public ContainersImageRemediation ImageRemediations { get; set; }

        [JsonProperty("imageLayers")]
        public ContainersImageLayers ImageLayers { get; set; }
    }

    public class ContainersVulnerabilitiesData
    {
        [JsonProperty("imagesVulnerabilities")]
        public ContainersPage<ContainersPackage> ImagesVulnerabilities { get; set; }
    }

    #endregion

    #region Images

    /// <summary>An image found by a Containers scan (query "images").</summary>
    public class ContainersImage
    {
        [JsonProperty("imageId")]
        public string ImageId { get; set; }

        [JsonProperty("imageName")]
        public string ImageName { get; set; }

        [JsonProperty("imageHash")]
        public string ImageHash { get; set; }

        [JsonProperty("baseImage")]
        public string BaseImage { get; set; }

        /// <summary>Highest severity of the image.</summary>
        [JsonProperty("severity")]
        public string Severity { get; set; }

        [JsonProperty("pkgCount")]
        public int? PkgCount { get; set; }

        [JsonProperty("vulnerablePkgCount")]
        public int? VulnerablePkgCount { get; set; }

        [JsonProperty("size")]
        public long? Size { get; set; }

        [JsonProperty("runtime")]
        public bool? Runtime { get; set; }

        [JsonProperty("fixable")]
        public bool? Fixable { get; set; }

        [JsonProperty("maliciousPackagesCount")]
        public int? MaliciousPackagesCount { get; set; }

        /// <summary>Text, not a flag (e.g. "Not Malicious").</summary>
        [JsonProperty("isImageMalicious")]
        public string IsImageMalicious { get; set; }

        /// <summary>Triage status of the image (e.g. Monitored, Snoozed).</summary>
        [JsonProperty("status")]
        public string Status { get; set; }

        [JsonProperty("snoozeDate")]
        public DateTime? SnoozeDate { get; set; }

        [JsonProperty("scanError")]
        public string ScanError { get; set; }

        /// <summary>Where the image comes from (Dockerfile, compose file, ...).</summary>
        [JsonProperty("groupsData")]
        public List<ContainersImageGroup> GroupsData { get; set; }

        [JsonProperty("vulnerabilities")]
        public ContainersSeverityCounts Vulnerabilities { get; set; }
    }

    public class ContainersImageGroup
    {
        [JsonProperty("filePath")]
        public string FilePath { get; set; }
    }

    /// <summary>Vulnerabilities of an image by severity.</summary>
    public class ContainersSeverityCounts
    {
        [JsonProperty("criticalCount")]
        public int? CriticalCount { get; set; }

        [JsonProperty("highCount")]
        public int? HighCount { get; set; }

        [JsonProperty("mediumCount")]
        public int? MediumCount { get; set; }

        [JsonProperty("lowCount")]
        public int? LowCount { get; set; }

        [JsonProperty("noneCount")]
        public int? NoneCount { get; set; }
    }

    #endregion

    #region Image detail (remediation and layers)

    /// <summary>Both answers of the image detail query: the remediation advice and the layers.</summary>
    public class ContainersImageDetail
    {
        public ContainersImageRemediation Remediation { get; set; }

        public ContainersImageLayers Layers { get; set; }
    }

    /// <summary>Is the base image outdated and which upgrade would remove the most vulnerabilities (query "imageRemediations").</summary>
    public class ContainersImageRemediation
    {
        [JsonProperty("isOutdated")]
        public bool? IsOutdated { get; set; }

        [JsonProperty("distribution")]
        public string Distribution { get; set; }

        [JsonProperty("vulnerabilitiesCount")]
        public int? VulnerabilitiesCount { get; set; }

        [JsonProperty("minorRecommendedImages")]
        public List<ContainersRecommendedImage> MinorRecommendedImages { get; set; }

        [JsonProperty("majorRecommendedImages")]
        public List<ContainersRecommendedImage> MajorRecommendedImages { get; set; }
    }

    public class ContainersRecommendedImage
    {
        [JsonProperty("imageId")]
        public string ImageId { get; set; }

        [JsonProperty("vulnerabilitiesCount")]
        public int? VulnerabilitiesCount { get; set; }

        [JsonProperty("criticalVulnerabilitiesCount")]
        public int? CriticalVulnerabilitiesCount { get; set; }

        [JsonProperty("highVulnerabilitiesCount")]
        public int? HighVulnerabilitiesCount { get; set; }
    }

    /// <summary>Which layers of the image come from which base image (FROM) (query "imageLayers").</summary>
    public class ContainersImageLayers
    {
        [JsonProperty("fixable")]
        public bool? Fixable { get; set; }

        [JsonProperty("fixableImage")]
        public bool? FixableImage { get; set; }

        [JsonProperty("fromImages")]
        public List<ContainersFromImage> FromImages { get; set; }
    }

    public class ContainersFromImage
    {
        [JsonProperty("imageName")]
        public string ImageName { get; set; }

        [JsonProperty("layers")]
        public List<ContainersLayer> Layers { get; set; }
    }

    public class ContainersLayer
    {
        [JsonProperty("layerId")]
        public string LayerId { get; set; }
    }

    #endregion

    #region Vulnerable packages

    /// <summary>A vulnerable package of an image, with its CVEs (query "imagesVulnerabilities").</summary>
    public class ContainersPackage
    {
        [JsonProperty("packageId")]
        public string PackageId { get; set; }

        [JsonProperty("packageName")]
        public string PackageName { get; set; }

        [JsonProperty("packageVersion")]
        public string PackageVersion { get; set; }

        [JsonProperty("type")]
        public string Type { get; set; }

        [JsonProperty("distribution")]
        public string Distribution { get; set; }

        [JsonProperty("maxRiskSeverity")]
        public string MaxRiskSeverity { get; set; }

        [JsonProperty("risksCount")]
        public int? RisksCount { get; set; }

        /// <summary>Triage status of the package.</summary>
        [JsonProperty("status")]
        public string Status { get; set; }

        [JsonProperty("snoozeDate")]
        public DateTime? SnoozeDate { get; set; }

        [JsonProperty("isStatusGlobal")]
        public bool? IsStatusGlobal { get; set; }

        [JsonProperty("imageTriageRegexes")]
        public List<string> ImageTriageRegexes { get; set; }

        [JsonProperty("imageTriageRegexStatus")]
        public string ImageTriageRegexStatus { get; set; }

        [JsonProperty("runtimeUsage")]
        public string RuntimeUsage { get; set; }

        [JsonProperty("isSource")]
        public bool? IsSource { get; set; }

        /// <summary>Text, not a flag (e.g. "Not Found").</summary>
        [JsonProperty("isMalicious")]
        public string IsMalicious { get; set; }

        /// <summary>Layers that bring the package; match them with <see cref="ContainersLayer.LayerId"/> to find its origin.</summary>
        [JsonProperty("layerIds")]
        public List<string> LayerIds { get; set; }

        [JsonProperty("aggregatedRisks")]
        public ContainersAggregatedRisks AggregatedRisks { get; set; }
    }

    public class ContainersAggregatedRisks
    {
        [JsonProperty("critical")]
        public int? Critical { get; set; }

        [JsonProperty("high")]
        public int? High { get; set; }

        [JsonProperty("medium")]
        public int? Medium { get; set; }

        [JsonProperty("low")]
        public int? Low { get; set; }

        [JsonProperty("none")]
        public int? None { get; set; }

        [JsonProperty("risksList")]
        public List<ContainersRisk> RisksList { get; set; }
    }

    /// <summary>A CVE of a package.</summary>
    public class ContainersRisk
    {
        [JsonProperty("cve")]
        public string Cve { get; set; }

        [JsonProperty("cwe")]
        public string Cwe { get; set; }

        /// <summary>Current severity, after triage.</summary>
        [JsonProperty("vulnerabilityLevel")]
        public string VulnerabilityLevel { get; set; }

        [JsonProperty("vulnerabilityScore")]
        public double? VulnerabilityScore { get; set; }

        [JsonProperty("originalSeverityLevel")]
        public string OriginalSeverityLevel { get; set; }

        [JsonProperty("originalScore")]
        public double? OriginalScore { get; set; }

        /// <summary>Severity given by the distro security advisory.</summary>
        [JsonProperty("originalAdvisorySeverity")]
        public string OriginalAdvisorySeverity { get; set; }

        /// <summary>The API sends it as text (e.g. "7.5"), and null when the advisory has no score.</summary>
        [JsonProperty("advisoryBaseScore")]
        public string AdvisoryBaseScore { get; set; }

        [JsonProperty("advisoryName")]
        public string AdvisoryName { get; set; }

        [JsonProperty("cvssVersion")]
        public string CvssVersion { get; set; }

        /// <summary>Result state (To Verify, Not Exploitable, ...); a custom state is in <see cref="CustomStateId"/>.</summary>
        [JsonProperty("state")]
        public string State { get; set; }

        [JsonProperty("customStateId")]
        public string CustomStateId { get; set; }

        [JsonProperty("isExploitable")]
        public bool? IsExploitable { get; set; }

        [JsonProperty("fixable")]
        public bool? Fixable { get; set; }

        [JsonProperty("fixedVersion")]
        public string FixedVersion { get; set; }

        [JsonProperty("publicationDate")]
        public DateTime? PublicationDate { get; set; }

        [JsonProperty("statusInfo")]
        public ContainersRiskStatusInfo StatusInfo { get; set; }
    }

    /// <summary>New / Recurrent status of a CVE and when it was first found.</summary>
    public class ContainersRiskStatusInfo
    {
        [JsonProperty("status")]
        public string Status { get; set; }

        [JsonProperty("firstScanId")]
        public string FirstScanId { get; set; }

        [JsonProperty("firstFoundDate")]
        public DateTime? FirstFoundDate { get; set; }
    }

    #endregion
}
