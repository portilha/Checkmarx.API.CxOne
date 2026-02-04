using Checkmarx.API.AST.Errors;
using Checkmarx.API.AST.Exceptions;
using Checkmarx.API.AST.Models.SCA;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using static Checkmarx.API.AST.ASTClient;
using JsonException = Newtonsoft.Json.JsonException;


namespace Checkmarx.API.AST.Services
{
    public partial class GraphQLClient
    {

        //private readonly GraphQLHttpClient _client;

#pragma warning disable 8618
        private string _baseUrl;
#pragma warning restore 8618

        private static System.Lazy<Newtonsoft.Json.JsonSerializerSettings> _settings = new System.Lazy<Newtonsoft.Json.JsonSerializerSettings>(CreateSerializerSettings, true);

        private readonly HttpClient _httpClient;

        public GraphQLClient(string endpointUri, HttpClient httpClient)
        {
            if (string.IsNullOrWhiteSpace(endpointUri))
                throw new ArgumentException("Endpoint URI cannot be null or empty", nameof(endpointUri));
            _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
            BaseUrl = endpointUri;

            //var options = new GraphQLHttpClientOptions
            //{
            //    EndPoint = new Uri(BaseUrl)
            //};

            //_client = new GraphQLHttpClient(options, new NewtonsoftJsonSerializer());
            //foreach (var item in _httpClient.DefaultRequestHeaders)
            //{
            //    _client.HttpClient.DefaultRequestHeaders.TryAddWithoutValidation(item.Key, item.Value);
            //}
        }


        private static Newtonsoft.Json.JsonSerializerSettings CreateSerializerSettings()
        {
            var settings = new Newtonsoft.Json.JsonSerializerSettings();
            UpdateJsonSerializerSettings(settings);
            return settings;
        }

        public string BaseUrl
        {
            get { return _baseUrl; }
            set
            {
                _baseUrl = value;
                if (!string.IsNullOrEmpty(_baseUrl) && !_baseUrl.EndsWith("/"))
                    _baseUrl += '/';
            }
        }

        protected Newtonsoft.Json.JsonSerializerSettings JsonSerializerSettings { get { return _settings.Value; } }

        static partial void UpdateJsonSerializerSettings(Newtonsoft.Json.JsonSerializerSettings settings);

        partial void PrepareRequest(System.Net.Http.HttpClient client, System.Net.Http.HttpRequestMessage request, string url);
        partial void PrepareRequest(System.Net.Http.HttpClient client, System.Net.Http.HttpRequestMessage request, System.Text.StringBuilder urlBuilder);
        partial void ProcessResponse(System.Net.Http.HttpClient client, System.Net.Http.HttpResponseMessage response);

        public async Task<string> ExecuteQueryAsync(string query, object variables = null)
        {
            if (string.IsNullOrWhiteSpace(query))
                throw new ArgumentException("Query cannot be null or empty", nameof(query));

            var requestBody = new
            {
                query,
                variables
            };

            var jsonContent = new StringContent(
                System.Text.Json.JsonSerializer.Serialize(requestBody),
                Encoding.UTF8,
                "application/json"
            );

            var response = await _retryPolicy.ExecuteAsync(() => _httpClient.PostAsync(BaseUrl, jsonContent)).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                throw new HttpRequestException($"Request failed with status code {response.StatusCode}: {errorContent}");
            }

            return await response.Content.ReadAsStringAsync();
        }

        public ICollection<ReportingPackage> GetSCAProjectsThanContainLibraryAsync(string packageName, IEnumerable<string> packageVersions, System.Threading.CancellationToken cancellationToken = default)
        {
            List<ReportingPackage> cveProjects = new List<ReportingPackage>();

            foreach (var versionsChunk in packageVersions.Chunk(1000))
            {
                cveProjects.AddRange(getSCAProjectsThanContainLibraryAsync(packageName, versionsChunk, cancellationToken).Result.Data.ReportingPackages);
            }

            return cveProjects;
        }

        public ScanLatestChanges GetSCAScanLatestChanges(Guid scanId)
        {
            if (scanId == Guid.Empty)
                throw new ArgumentNullException(nameof(scanId));

            var query = @"query ($scanId: UUID!) { scanLatestChanges (scanId: $scanId) { supplyChainRiskChangesCounter, vulnerabilityModelChangesCounter, packageModelChangesCounter, directPackagesChangeCounter, transitivePackagesChangeCounter, licenseModelChangesCounter } }";

            // Define variables for the query
            var variables = new
            {
                scanId = scanId
            };

            var response = ExecuteQueryAsync(query, variables).GetAwaiter().GetResult();

            return System.Text.Json.JsonSerializer.Deserialize<ScanLatestChanges>(
                response,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
            );
        }

        /// <summary>
        /// Calls the GraphQL API to search for package vulnerability state and score actions.
        /// </summary>
        /// <param name="variables">An object containing the query variables.</param>
        /// <returns>A <see cref="GraphQLResponse"/> object containing the deserialized API response.</returns>
        /// <exception cref="HttpRequestException">Thrown if the HTTP request fails.</exception>
        /// <exception cref="JsonException">Thrown if JSON deserialization fails.</exception>
        public async Task<ICollection<ScaActionItem>> SearchPackageVulnerabilityActionsAsync(
            PackageVulnerabilityStateAndScoreActionsVariables variables)
        {

            // The GraphQL query string
            const string PackageVulnerabilityQuery = @"
            query ($scanId: UUID!, $projectId: String, $isLatest: Boolean!, $packageName: String, $packageVersion: String, $packageManager: String, $vulnerabilityId: String) {
                searchPackageVulnerabilityStateAndScoreActions (
                    scanId: $scanId,
                    projectId: $projectId,
                    isLatest: $isLatest,
                    packageName: $packageName,
                    packageVersion: $packageVersion,
                    packageManager: $packageManager,
                    vulnerabilityId: $vulnerabilityId
                ) {
                    actions {
                        isComment,
                        actionType,
                        actionValue,
                        enabled,
                        createdAt,
                        previousActionValue,
                        comment {
                            id,
                            message,
                            createdOn,
                            userName
                        }
                    }
                }
            }";

            // Create the GraphQL request payload
            var requestBody = new GraphQLRequest<PackageVulnerabilityStateAndScoreActionsVariables>
            {
                Query = PackageVulnerabilityQuery,
                Variables = variables
            };

            // Serialize the request body to JSON
            // JsonContent.Create handles setting Content-Type: application/json
            var content = JsonContent.Create(requestBody, options: new JsonSerializerOptions { WriteIndented = true });

            HttpResponseMessage response = null;

            try
            {
                // Send the POST request
                response = await _retryPolicy.ExecuteAsync(() => _httpClient.PostAsync(BaseUrl, content)).ConfigureAwait(false);

                // Ensure the request was successful; throws HttpRequestException for non-success status codes
                response.EnsureSuccessStatusCode();

                // Read the response content as a string
                string responseBody = await response.Content.ReadAsStringAsync();

                // Deserialize the JSON response using Newtonsoft.Json
                var graphQlResponse = JsonConvert.DeserializeObject<GraphQLResponse>(responseBody);

                if (graphQlResponse.Data.SearchPackageVulnerabilityStateAndScoreActions != null)
                    return graphQlResponse.Data.SearchPackageVulnerabilityStateAndScoreActions.Actions;

                return [];
            }
            catch (HttpRequestException ex)
            {
                Console.WriteLine($"HTTP Request Error: {ex.StatusCode} - {ex.Message}");
                // Optionally read response body for more details on error
                string errorContent = await (response?.Content?.ReadAsStringAsync() ?? Task.FromResult(""));
                Console.WriteLine($"Error Response Body: {errorContent}");
                throw; // Re-throw the exception after logging
            }
            catch (JsonException ex)
            {
                Console.WriteLine($"JSON Deserialization Error: {ex.Message}");
                throw; // Re-throw the exception after logging
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An unexpected error occurred: {ex.Message}");
                throw; // Re-throw the exception
            }
        }

        /// <summary>
        /// Calls the GraphQL API to fetch all vulnerabilities for a given scan ID, handling pagination.
        /// </summary>
        /// <param name="initialVariables">The initial variables for the query (scanId, isExploitablePathEnabled, where, order).
        ///                                  Take and Skip will be managed by the method.</param>
        /// <param name="pageSize">The number of items to request per page. Default is 100.</param>
        /// <returns>A list of <see cref="Vulnerability"/> objects.</returns>
        /// <exception cref="HttpRequestException">Thrown if an HTTP request fails.</exception>
        /// <exception cref="JsonException">Thrown if JSON deserialization fails.</exception>
        public async Task<List<ScaVulnerability>> GetAllVulnerabilitiesRisksByScanIdAsync(
            VulnerabilitiesRisksByScanIdVariables initialVariables,
            int pageSize = 100)
        {
            const string VulnerabilitiesRisksQuery = @"
            query ($where: VulnerabilityModelFilterInput, $take: Int!, $skip: Int!, $order: [VulnerabilitiesSort!], $scanId: UUID!, $isExploitablePathEnabled: Boolean!) {
                vulnerabilitiesRisksByScanId (
                    where: $where,
                    take: $take,
                    skip: $skip,
                    order: $order,
                    scanId: $scanId,
                    isExploitablePathEnabled: $isExploitablePathEnabled
                ) {
                    totalCount,
                    items {
                        credit, state, isIgnored, cve, cwe, description, packageId, severity, type, published, score, violatedPolicies, isExploitable, exploitabilityReason, exploitabilityStatus, isKevDataExists, isExploitDbDataExists, vulnerabilityFixResolutionText, relation, epssData { cve, date, epss, percentile }, isEpssDataExists, detectionDate, isVulnerabilityNew, cweInfo { title }, packageInfo { name, packageRepository, version }, exploitablePath { methodMatch { fullName, line, namespace, shortName, sourceFile }, methodSourceCall { fullName, line, namespace, shortName, sourceFile } }, vulnerablePackagePath { id, isDevelopment, isResolved, name, version, vulnerabilityRiskLevel }, references { comment, type, url }, cvss2 { attackComplexity, attackVector, authentication, availability, availabilityRequirement, baseScore, collateralDamagePotential, confidentiality, confidentialityRequirement, exploitCodeMaturity, integrityImpact, integrityRequirement, remediationLevel, reportConfidence, targetDistribution }, cvss3 { attackComplexity, attackVector, availability, availabilityRequirement, baseScore, confidentiality, confidentialityRequirement, exploitCodeMaturity, integrity, integrityRequirement, privilegesRequired, remediationLevel, reportConfidence, scope, userInteraction }, cvss4 { attackComplexity, attackVector, attackRequirements, baseScore, privilegesRequired, userInteraction, vulnerableSystemConfidentiality, vulnerableSystemIntegrity, vulnerableSystemAvailability, subsequentSystemConfidentiality, subsequentSystemIntegrity, subsequentSystemAvailability }, pendingState, pendingChanges, packageState { type, value }, pendingScore, pendingSeverity, isScoreOverridden
                    }
                }
            }";

            int skip = 0;
            int totalCount = 0;
            bool firstRequest = true;

            // Clone the initial variables to avoid modifying the caller's object
            var currentVariables = new VulnerabilitiesRisksByScanIdVariables
            {
                ScanId = initialVariables.ScanId,
                IsExploitablePathEnabled = initialVariables.IsExploitablePathEnabled,
                Where = initialVariables.Where,
                Order = initialVariables.Order,
                Take = pageSize, // Set initial take
                Skip = 0 // Start with skip 0
            };

            var allVulnerabilities = new List<ScaVulnerability>();

            do
            {
                currentVariables.Skip = skip; // Set the current skip value

                var requestBody = new GraphQLRequest<VulnerabilitiesRisksByScanIdVariables>
                {
                    Query = VulnerabilitiesRisksQuery,
                    Variables = currentVariables
                };

                var content = JsonContent.Create(requestBody, options: new JsonSerializerOptions { });

                try
                {
                    var response = await _retryPolicy.ExecuteAsync(() => _httpClient.PostAsync(BaseUrl, content)).ConfigureAwait(false);

                    response.EnsureSuccessStatusCode();

                    // Read the response content as a string
                    string responseBody = await response.Content.ReadAsStringAsync();

                    // Deserialize the JSON response using Newtonsoft.Json
                    var graphQlResponse = JsonConvert.DeserializeObject<GraphQLResponseVulnerabilities>(responseBody);

                    if (graphQlResponse?.Data?.VulnerabilitiesRisksByScanId?.Items != null)
                    {
                        if (firstRequest)
                        {
                            totalCount = graphQlResponse.Data.VulnerabilitiesRisksByScanId.TotalCount;
                            firstRequest = false;
                            // Console.WriteLine($"Total vulnerabilities found: {totalCount}");
                        }

                        allVulnerabilities.AddRange(graphQlResponse.Data.VulnerabilitiesRisksByScanId.Items);
                        skip += graphQlResponse.Data.VulnerabilitiesRisksByScanId.Items.Count; // Increment skip by actual items received
                        // Console.WriteLine($"Fetched {graphQlResponse.Data.VulnerabilitiesRisksByScanId.Items.Count} items. Total fetched: {allVulnerabilities.Count}/{totalCount}");
                    }
                    else
                    {
                        Console.WriteLine("No items found in the current page or response data is null.");
                        break; // Exit loop if no items are returned, indicating end of data or an issue
                    }
                }
                catch (HttpRequestException ex)
                {
                    Console.WriteLine($"HTTP Request Error during pagination: {ex.StatusCode} - {ex.Message}");
                    throw;
                }
                catch (Newtonsoft.Json.JsonException ex)
                {
                    Console.WriteLine($"JSON Deserialization Error during pagination: {ex.Message}");
                    throw;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"An unexpected error occurred during pagination: {ex.Message}");
                    throw;
                }

            } while (skip < totalCount); // Continue if more items are expected

            return allVulnerabilities;
        }


        public async Task<ICollection<ReportingRisk>> GetAllVulnerabilitiesAsync(int take = 1000)
        {
            int skip = 0;
            bool hasMore = true;

            var allVulnerabilities = new List<ReportingRisk>();

            while (hasMore)
            {
                var requestBody = new
                {
                    query = @"query ($where: ReportingRiskModelFilterInput, $take: Int!, $skip: Int!, $order: [ReportingRiskModelSortInput!]) {
                                reportingRisks (where: $where, take: $take, skip: $skip, order: $order) {
                                    scanId, projectId, severity, pendingSeverity, riskType, vulnerabilityId,
                                    packageId, packageName, packageVersion, projectName, vulnerabilityPublicationDate,
                                    score, pendingScore, state, pendingState, scanDate, epssPercentile, epss,
                                    isExploitable, exploitabilityReason, exploitabilityStatus, kevDataExists,
                                    exploitDbDataExist, epssDataExists, detectionDate, cwe, cweTitle, isFixAvailable,
                                    fixRecommendationVersion
                                }
                            }",
                    variables = new
                    {
                        where = (object)null,
                        take,
                        skip,
                        order = new[] { new { score = "DESC" } }
                    }
                };

                using (var request_ = new System.Net.Http.HttpRequestMessage())
                {
                    var content = JsonContent.Create(requestBody, options: new JsonSerializerOptions { });

                    var response = await _retryPolicy.ExecuteAsync(() => _httpClient.PostAsync(BaseUrl, content)).ConfigureAwait(false);

                    response.EnsureSuccessStatusCode();

                    // Read the response content as a string
                    string responseBody = await response.Content.ReadAsStringAsync();

                    // Deserialize the JSON response using Newtonsoft.Json
                    var result = JsonConvert.DeserializeObject<GraphQLResponseReportingRisk>(responseBody);

                    if (result?.Data?.ReportingRisks is not null && result.Data.ReportingRisks.Count > 0)
                    {
                        allVulnerabilities.AddRange(result.Data.ReportingRisks);
                        skip += take;
                    }
                    else
                    {
                        hasMore = false;
                    }
                }
            }

            return allVulnerabilities;
        }

        private async Task<CveProjects> getSCAProjectsThanContainLibraryAsync(string packageName, IEnumerable<string> packageVersions, System.Threading.CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(packageName))
                throw new ArgumentException("Library name cannot be null or empty", nameof(packageName));

            var urlBuilder_ = new System.Text.StringBuilder();
            urlBuilder_.Append(BaseUrl != null ? BaseUrl.TrimEnd('/') : "");

            StringBuilder whereClause = new StringBuilder();

            whereClause.Append($" {{ \"and\": [ {{ \"packageName\": {{ \"eq\": \"{packageName}\" }}  }},                {{                     \"or\": [ {string.Join(",", packageVersions.Select(x => $"{{ \"packageVersion\":  {{ \"eq\":  \"{x}\" }}  }}"))} ]                }} ]                }}");

            string queryForProject = $"{{    \"query\": \"query ($where: ReportingPackageModelFilterInput, $take: Int!, $skip: Int!, $order: [ReportingPackageModelSortInput!], $searchTerm: String) {{ reportingPackages (where: $where, take: $take, skip: $skip, order: $order, searchTerm: $searchTerm) {{ projectId, projectName, packageName, packageVersion, scanId }} }}\",    \"variables\": {{        \"where\": {whereClause.ToString()},        \"take\": 1000,        \"skip\": 0,        \"order\": [            {{                \"isMalicious\": \"DESC\"            }}        ]    }}}}";

            var client_ = _httpClient;
            var disposeClient_ = false;
            try
            {
                using (var request_ = new System.Net.Http.HttpRequestMessage())
                {
                    var content_ = new System.Net.Http.StringContent(queryForProject);
                    content_.Headers.ContentType = System.Net.Http.Headers.MediaTypeHeaderValue.Parse("application/json");
                    request_.Content = content_;

                    request_.Method = new System.Net.Http.HttpMethod("POST");

                    PrepareRequest(client_, request_, urlBuilder_);

                    var url_ = urlBuilder_.ToString();
                    request_.RequestUri = new System.Uri(url_, System.UriKind.RelativeOrAbsolute);

                    PrepareRequest(client_, request_, url_);

                    var response_ = await _retryPolicy.ExecuteAsync(() => client_.SendAsync(CloneHttpRequestMessage(request_), System.Net.Http.HttpCompletionOption.ResponseHeadersRead, cancellationToken)).ConfigureAwait(false);
                    var disposeResponse_ = true;
                    try
                    {
                        var headers_ = System.Linq.Enumerable.ToDictionary(response_.Headers, h_ => h_.Key, h_ => h_.Value);
                        if (response_.Content != null && response_.Content.Headers != null)
                        {
                            foreach (var item_ in response_.Content.Headers)
                                headers_[item_.Key] = item_.Value;
                        }

                        ProcessResponse(client_, response_);

                        var status_ = (int)response_.StatusCode;
                        if (status_ == 200)
                        {
                            var objectResponse_ = await ReadObjectResponseAsync<CveProjects>(response_, headers_, cancellationToken).ConfigureAwait(false);
                            if (objectResponse_.Object == null)
                            {
                                throw new ApiException("Response was null which was not expected.", status_, objectResponse_.Text, headers_, null);
                            }
                            return objectResponse_.Object;
                        }
                        else
                        if (status_ == 400)
                        {
                            var objectResponse_ = await ReadObjectResponseAsync<WebError>(response_, headers_, cancellationToken).ConfigureAwait(false);
                            if (objectResponse_.Object == null)
                            {
                                throw new ApiException("Response was null which was not expected.", status_, objectResponse_.Text, headers_, null);
                            }
                            throw new ApiException<WebError>("Invalid request supplied.", status_, objectResponse_.Text, headers_, objectResponse_.Object, null);
                        }
                        else
                        {
                            var responseData_ = response_.Content == null ? null : await response_.Content.ReadAsStringAsync().ConfigureAwait(false);
                            throw new ApiException("The HTTP status code of the response was not expected (" + status_ + ").", status_, responseData_, headers_, null);
                        }
                    }
                    finally
                    {
                        if (disposeResponse_)
                            response_.Dispose();
                    }
                }
            }
            finally
            {
                if (disposeClient_)
                    client_.Dispose();
            }
        }

        public SCALegalRisks GetSCAScanLegalRisks(string query, object variables = null)
        {
            var response = ExecuteQueryAsync(query, variables).GetAwaiter().GetResult();
            return System.Text.Json.JsonSerializer.Deserialize<SCALegalRisks>(
                response,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
            );
        }

        protected struct ObjectResponseResult<T>
        {
            public ObjectResponseResult(T responseObject, string responseText)
            {
                this.Object = responseObject;
                this.Text = responseText;
            }

            public T Object { get; }

            public string Text { get; }
        }

        public bool ReadResponseAsString { get; set; }

        protected virtual async System.Threading.Tasks.Task<ObjectResponseResult<T>> ReadObjectResponseAsync<T>(System.Net.Http.HttpResponseMessage response, System.Collections.Generic.IReadOnlyDictionary<string, System.Collections.Generic.IEnumerable<string>> headers, System.Threading.CancellationToken cancellationToken)
        {
            if (response == null || response.Content == null)
            {
                return new ObjectResponseResult<T>(default, string.Empty);
            }

            if (ReadResponseAsString)
            {
                var responseText = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                try
                {
                    var typedBody = Newtonsoft.Json.JsonConvert.DeserializeObject<T>(responseText, JsonSerializerSettings);
                    return new ObjectResponseResult<T>(typedBody, responseText);
                }
                catch (Newtonsoft.Json.JsonException exception)
                {
                    var message = "Could not deserialize the response body string as " + typeof(T).FullName + ".";
                    throw new ApiException(message, (int)response.StatusCode, responseText, headers, exception);
                }
            }
            else
            {
                try
                {
                    using (var responseStream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false))
                    using (var streamReader = new System.IO.StreamReader(responseStream))
                    using (var jsonTextReader = new Newtonsoft.Json.JsonTextReader(streamReader))
                    {
                        var serializer = Newtonsoft.Json.JsonSerializer.Create(JsonSerializerSettings);
                        var typedBody = serializer.Deserialize<T>(jsonTextReader);
                        return new ObjectResponseResult<T>(typedBody, string.Empty);
                    }
                }
                catch (Newtonsoft.Json.JsonException exception)
                {
                    var message = "Could not deserialize the response body stream as " + typeof(T).FullName + ".";
                    throw new ApiException(message, (int)response.StatusCode, string.Empty, headers, exception);
                }
            }
        }

        private string ConvertToString(object value, System.Globalization.CultureInfo cultureInfo)
        {
            if (value == null)
            {
                return "";
            }

            if (value is System.Enum)
            {
                var name = System.Enum.GetName(value.GetType(), value);
                if (name != null)
                {
                    var field = System.Reflection.IntrospectionExtensions.GetTypeInfo(value.GetType()).GetDeclaredField(name);
                    if (field != null)
                    {
                        var attribute = System.Reflection.CustomAttributeExtensions.GetCustomAttribute(field, typeof(System.Runtime.Serialization.EnumMemberAttribute))
                            as System.Runtime.Serialization.EnumMemberAttribute;
                        if (attribute != null)
                        {
                            return attribute.Value != null ? attribute.Value : name;
                        }
                    }

                    var converted = System.Convert.ToString(System.Convert.ChangeType(value, System.Enum.GetUnderlyingType(value.GetType()), cultureInfo));
                    return converted == null ? string.Empty : converted;
                }
            }
            else if (value is bool)
            {
                return System.Convert.ToString((bool)value, cultureInfo).ToLowerInvariant();
            }
            else if (value is byte[])
            {
                return System.Convert.ToBase64String((byte[])value);
            }
            else if (value is string[])
            {
                return string.Join(",", (string[])value);
            }
            else if (value.GetType().IsArray)
            {
                var valueArray = (System.Array)value;
                var valueTextArray = new string[valueArray.Length];
                for (var i = 0; i < valueArray.Length; i++)
                {
                    valueTextArray[i] = ConvertToString(valueArray.GetValue(i), cultureInfo);
                }
                return string.Join(",", valueTextArray);
            }

            var result = System.Convert.ToString(value, cultureInfo);
            return result == null ? "" : result;
        }

    }

    // === Models ===
    public class GraphQLResponseReportingRisk
    {
        [JsonPropertyName("data")]
        public DataWrapperReportingRisk Data { get; set; }
    }

    public class DataWrapperReportingRisk
    {
        [JsonPropertyName("reportingRisks")]
        public List<ReportingRisk> ReportingRisks { get; set; }
    }

    public class ReportingRisk
    {
        public string ScanId { get; set; }
        public string ProjectId { get; set; }
        public string Severity { get; set; }
        public string PendingSeverity { get; set; }
        public string RiskType { get; set; }
        public string VulnerabilityId { get; set; }
        public string PackageId { get; set; }
        public string PackageName { get; set; }
        public string PackageVersion { get; set; }
        public string ProjectName { get; set; }
        public DateTime? VulnerabilityPublicationDate { get; set; }
        public double? Score { get; set; }
        public double? PendingScore { get; set; }
        public string State { get; set; }
        public string PendingState { get; set; }
        public DateTime? ScanDate { get; set; }
        public double? EpssPercentile { get; set; }
        public double? Epss { get; set; }
        public bool? IsExploitable { get; set; }
        public string ExploitabilityReason { get; set; }
        public string ExploitabilityStatus { get; set; }
        public bool? KevDataExists { get; set; }
        public bool? ExploitDbDataExist { get; set; }
        public bool? EpssDataExists { get; set; }
        public DateTime? DetectionDate { get; set; }
        public string Cwe { get; set; }
        public string CweTitle { get; set; }
        public bool? IsFixAvailable { get; set; }
        public string FixRecommendationVersion { get; set; }
    }
}
