using Checkmarx.API.AST.Enums;
using Checkmarx.API.AST.Models;
using Checkmarx.API.AST.Models.Report;
using Checkmarx.API.AST.Models.SCA;
using Checkmarx.API.AST.Services;
using Checkmarx.API.AST.Services.Analytics;
using Checkmarx.API.AST.Services.Applications;
using Checkmarx.API.AST.Services.Audit;
using Checkmarx.API.AST.Services.Configuration;
using Checkmarx.API.AST.Services.CustomStates;
using Checkmarx.API.AST.Services.KicsResults;
using Checkmarx.API.AST.Services.Projects;
using Checkmarx.API.AST.Services.QueryEditor;
using Checkmarx.API.AST.Services.Reports;
using Checkmarx.API.AST.Services.ReportsV2;
using Checkmarx.API.AST.Services.Repostore;
using Checkmarx.API.AST.Services.ResultsOverview;
using Checkmarx.API.AST.Services.ResultsSummary;
using Checkmarx.API.AST.Services.SASTMetadata;
using Checkmarx.API.AST.Services.SASTQueriesAudit;
using Checkmarx.API.AST.Services.SASTResults;
using Checkmarx.API.AST.Services.SASTResultsPredicates;
using Checkmarx.API.AST.Services.SASTScanResultsCompare;
using Checkmarx.API.AST.Services.ScannersResults;
using Checkmarx.API.AST.Services.Scans;
using Checkmarx.API.AST.Services.Uploads;
using Checkmarx.API.AST.Utils;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Polly;
using Polly.Extensions.Http;
using Polly.Timeout;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Data;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;

namespace Checkmarx.API.AST
{
    public struct CxOneConnection
    {
        public Uri CxOneServer;
        public Uri AccessControlServer;
        public string Tenant;
        public string ApiKey;
    }

    public class ASTClient
    {
        public Uri AccessControlServer { get; private set; }
        public Uri ASTServer { get; private set; }
        public string Tenant { get; }
        public string KeyApi { get; set; }
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }

        public const string SettingsAPISecuritySwaggerFolderFileFilter = "scan.config.apisec.swaggerFilter";
        public const string SettingsProjectRepoUrl = "scan.handler.git.repository";
        public const string SettingsProjectExclusions = "scan.config.sast.filter";
        public const string SettingsProjectConfiguration = "scan.config.sast.languageMode";
        public const string SettingsProjectPreset = "scan.config.sast.presetName";
        public const string FastScanConfiguration = "scan.config.sast.fastScanMode";
        public const string RecommendedExclusionsConfiguration = "scan.config.sast.recommendedExclusions";
        public const string IsIncrementalConfiguration = "scan.config.sast.incremental";
        public const string SettingsResultsScopeLevel = "scan.config.sast.resultsScopeLevel";


        public const string SAST_Engine = "sast";
        public const string SCA_Engine = "sca";
        public const string KICS_Engine = "kics";
        public const string API_Security_Engine = "apisec";
        public const string SCA_Container_Engine = "sca-container";

        public const string Query_Level_Cx = "Cx";
        public const string Query_Level_Tenant = "Tenant";
        public const string Query_Level_Application = "Application";
        public const string Query_Level_Project = "Project";

        public const string Feature_Flag_CustomStatesEnabled = "CUSTOM_STATES_ENABLED";

        private const string Claim_License = "ast-license";

        private readonly static string CompletedStage = Checkmarx.API.AST.Services.Scans.Status.Completed.ToString();

        #region HttpClient and Policies

        // Which request the shared _retryPolicy below is currently retrying — every generated
        // Services/*.cs client sends through _httpClient, so RequestDescriptionHandler (wrapped around
        // its inner SocketsHttpHandler) sees every one of those requests generically, with no need to
        // touch 40+ generated files individually the way QueryEditorClient's own dedicated policy does
        // (that one also needed request-body access and level of control specific to sessions, which
        // is why it stayed separate rather than folding into this same mechanism).
        // AsyncLocal, not a plain field: each concurrent call gets its own value with no cross-talk,
        // and a set doesn't leak back up to the caller once the request completes.
        internal static readonly AsyncLocal<string> _currentRequestDescription = new AsyncLocal<string>();

        private sealed class RequestDescriptionHandler : DelegatingHandler
        {
            public RequestDescriptionHandler(HttpMessageHandler innerHandler) : base(innerHandler) { }

            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                _currentRequestDescription.Value = $"{request.Method} {request.RequestUri}";
                return base.SendAsync(request, cancellationToken);
            }
        }

        private readonly HttpClient _httpClient = new HttpClient(new RequestDescriptionHandler(new SocketsHttpHandler
        {
            // Proactively recycle pooled connections instead of holding them open indefinitely.
            // Long-running exports (many hours) were hitting "connection forcibly closed by remote
            // host" / "response ended prematurely" because a server-side proxy/gateway was killing
            // connections the pool still thought were alive.
            PooledConnectionLifetime = TimeSpan.FromMinutes(3),
            PooledConnectionIdleTimeout = TimeSpan.FromMinutes(1)
        }))
        {
            // We don’t want HttpClient controlling timeouts — we want Polly to control them
            // We are just adding a big timeout just as a safety net in case Polly somehow fails to cancel
            Timeout = TimeSpan.FromMinutes(10)
        };

        internal static readonly IAsyncPolicy<HttpResponseMessage> _retryPolicy = createPolicy();

        private static IAsyncPolicy<HttpResponseMessage> createPolicy()
        {
            var timeouts = new[]
            {
                TimeSpan.FromSeconds(60),
                TimeSpan.FromSeconds(120),
                TimeSpan.FromSeconds(240)
            };

            const string TimeoutAttemptKey = "TimeoutAttempt";

            // Inner timeout policy: reads the attempt number from Context
            var timeoutPolicy = Policy.TimeoutAsync<HttpResponseMessage>(
                context =>
                {
                    int attempt = context.TryGetValue(TimeoutAttemptKey, out var val) ? (int)val : 0;
                    return timeouts[Math.Min(attempt, timeouts.Length - 1)];
                },
                TimeoutStrategy.Pessimistic
            );

            // Timeout retry policy: increments the attempt in Context, wraps the timeout policy
            var timeoutRetryPolicy = Policy<HttpResponseMessage>
                .Handle<TimeoutRejectedException>()
                .RetryAsync(
                    timeouts.Length - 1, // 2 retries = 3 total attempts
                    (outcome, retryCount, context) =>
                    {
                        // Increment the per-execution attempt counter
                        int current = context.TryGetValue(TimeoutAttemptKey, out var val) ? (int)val : 0;
                        context[TimeoutAttemptKey] = current + 1;

                        TimeSpan nextTimeout = timeouts[Math.Min(current + 1, timeouts.Length - 1)];
                        Console.WriteLine(
                            $"Timeout retry {retryCount}/{timeouts.Length - 1} — " +
                            $"next timeout: {nextTimeout.TotalSeconds}s. " +
                            $"Reason: {outcome.Exception?.Message ?? "unknown"}");
                    });

            // Existing transient/429 retry policy (unchanged)
            var transientRetryPolicy = HttpPolicyExtensions
                .HandleTransientHttpError()
                .OrResult(r => r.StatusCode == System.Net.HttpStatusCode.TooManyRequests)
                .WaitAndRetryAsync(
                    10,
                    retryAttempt =>
                        TimeSpan.FromSeconds(Math.Min(Math.Pow(2, retryAttempt), 30)) +
                        TimeSpan.FromMilliseconds(Random.Shared.Next(0, 1000)),
                    (outcome, timeSpan, retryCount, context) =>
                    {
                        string requestDescription = _currentRequestDescription.Value;
                        Console.WriteLine(
                            $"Transient retry {retryCount}/10 after {timeSpan.TotalSeconds:F1}s. " +
                            $"Reason: {(outcome.Exception != null ? outcome.Exception.Message : $"{(int?)outcome.Result?.StatusCode} {outcome.Result?.ReasonPhrase}")}" +
                            (string.IsNullOrEmpty(requestDescription) ? "" : $" | {requestDescription}"));
                    });

            // Wrap order matters:
            // transientRetryPolicy (outermost) → timeoutRetryPolicy → timeoutPolicy (innermost)
            return Policy.WrapAsync(transientRetryPolicy, timeoutRetryPolicy, timeoutPolicy);
        }

        // Helper method to clone HttpRequestMessage
        public static HttpRequestMessage CloneHttpRequestMessage(HttpRequestMessage request)
        {
            var clone = new HttpRequestMessage(request.Method, request.RequestUri);

            // Clone request content (if any)
            if (request.Content != null)
            {
                clone.Content = getHttpContentClone(request.Content);
                clone.Content.Headers.Clear();
                foreach (var header in request.Content.Headers)
                    clone.Content.Headers.Add(header.Key, header.Value);
            }

            // Clone the request headers
            foreach (var header in request.Headers)
            {
                clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }

            // Copy other properties (e.g., Version)
            clone.Version = request.Version;

            return clone;
        }

        private static HttpContent getHttpContentClone(HttpContent content)
        {
            if (content == null)
                throw new ArgumentNullException(nameof(content));

            if (content is StreamContent)
            {
                return new StreamContent(content.ReadAsStreamAsync().Result);
            }
            else if (content is StringContent)
            {
                return new StringContent(content.ReadAsStringAsync().Result);
            }
            else if (content is ByteArrayContent)
            {
                return new ByteArrayContent(content.ReadAsByteArrayAsync().Result);
            }
            else if (content is FormUrlEncodedContent)
            {
                return new FormUrlEncodedContent(content.ReadAsStringAsync().Result.Split('&').Select(pair =>
                {
                    var kv = pair.Split('=');
                    return new KeyValuePair<string, string>(kv[0], kv.Length > 1 ? kv[1] : "");
                }));
            }
            else if (content is MultipartFormDataContent)
            {
                var multiPartContent = (MultipartFormDataContent)content;
                var newMultipartContent = new MultipartFormDataContent();
                foreach (var partContent in multiPartContent)
                {
                    newMultipartContent.Add(partContent, partContent.Headers.ContentDisposition.Name, partContent.Headers.ContentDisposition.FileName);
                }
                return newMultipartContent;
            }
            else
            {
                throw new NotSupportedException($"Unsupported content type: {content.GetType()}");
            }
        }

        #endregion

        #region Services

        private GraphQLClient _graphql;
        public GraphQLClient GraphQLClient
        {
            get
            {
                if (Connected && _graphql == null)
                    _graphql = new GraphQLClient($"{ASTServer.AbsoluteUri}api/sca/graphql/graphql", _httpClient);

                return _graphql;
            }
        }

        private Projects _projects;
        public Projects Projects
        {
            get
            {
                if (Connected && _projects == null)
                    _projects = new Projects($"{ASTServer.AbsoluteUri}api/projects", _httpClient);

                return _projects;
            }
        }

        private Analytics _analytics;
        public Analytics Analytics
        {
            get
            {
                if (Connected && _analytics == null)
                    _analytics = new Analytics($"{ASTServer.AbsoluteUri}api/data_analytics", _httpClient);

                return _analytics;
            }
        }

        private FeatureFlags _featureFlags;
        public FeatureFlags FeatureFlags
        {
            get
            {
                if (Connected && _featureFlags == null)
                    _featureFlags = new FeatureFlags(ASTServer, _httpClient);

                return _featureFlags;
            }
        }

        private Integrations _integrations;
        public Integrations Integrations
        {
            get
            {
                if (Connected && _integrations == null)
                    _integrations = new Integrations(ASTServer, _httpClient);

                return _integrations;
            }
        }

        private Lists _lists;
        public Lists Lists
        {
            get
            {
                if (Connected && _lists == null)
                    _lists = new Lists(ASTServer, _httpClient);

                return _lists;
            }
        }

        private Scans _scans;
        public Scans Scans
        {
            get
            {
                if (Connected && _scans == null)
                    _scans = new Scans($"{ASTServer.AbsoluteUri}api/scans", _httpClient);

                return _scans;
            }
        }

        private ReportsV2 _reportsV2;
        public ReportsV2 ReportsV2
        {
            get
            {
                if (Connected && _reportsV2 == null)
                    _reportsV2 = new ReportsV2(ASTServer, _httpClient);

                return _reportsV2;
            }
        }

        private Reports _reports;
        public Reports Reports
        {
            get
            {
                if (Connected && _reports == null)
                    _reports = new Reports($"{ASTServer.AbsoluteUri}api/reports", _httpClient);

                return _reports;
            }
        }

        private Requests _requests;
        public Requests Requests
        {
            get
            {
                if (Connected && _requests == null)
                    _requests = new Requests(ASTServer, _httpClient);

                return _requests;
            }
        }


        private API_Risks _api_risks;
        public API_Risks API_Risks
        {
            get
            {
                if (Connected && _api_risks == null)
                    _api_risks = new API_Risks(ASTServer, _httpClient);

                return _api_risks;
            }
        }


        private AccessManagement _accessManagement;
        public AccessManagement AccessManagement
        {
            get
            {
                if (Connected && _accessManagement == null)
                    _accessManagement = new AccessManagement(ASTServer, _httpClient);

                return _accessManagement;
            }
        }

        private CustomStates _customStates;
        public CustomStates CustomStates
        {
            get
            {
                if (Connected && _customStates == null)
                    _customStates = new CustomStates(ASTServer, _httpClient);

                return _customStates;
            }
        }


        private SASTMetadata _SASTMetadata;
        public SASTMetadata SASTMetadata
        {
            get
            {
                if (Connected && _SASTMetadata == null)
                    _SASTMetadata = new SASTMetadata($"{ASTServer.AbsoluteUri}api/sast-metadata", _httpClient);

                return _SASTMetadata;
            }
        }

        private Applications _applications;
        public Applications Applications
        {
            get
            {
                if (Connected && _applications == null)
                    _applications = new Applications($"{ASTServer.AbsoluteUri}api/applications", _httpClient);

                return _applications;
            }
        }

        private AuditTrail _audit;
        public AuditTrail Audit
        {
            get
            {
                if (Connected && _audit == null)
                    _audit = new AuditTrail($"{ASTServer.AbsoluteUri}api/audit", _httpClient);

                return _audit;
            }
        }

        private AuditEventProcessor _auditEventProcessor;
        public AuditEventProcessor AuditEventProcessor
        {
            get
            {
                if (Connected && _auditEventProcessor == null)
                    _auditEventProcessor = new AuditEventProcessor($"{ASTServer.AbsoluteUri}api/audit-events", _httpClient);

                return _auditEventProcessor;
            }
        }

        private Versions _engineVersions;
        public Versions EngineVersions
        {
            get
            {
                if (Connected && _engineVersions == null)
                    _engineVersions = new Versions(ASTServer, _httpClient);

                return _engineVersions;
            }
        }

        private SSCSReader _sscsReader;
        public SSCSReader SSCS
        {
            get
            {
                if (Connected && _sscsReader == null)
                    _sscsReader = new SSCSReader(ASTServer, _httpClient);

                return _sscsReader;
            }
        }

        private AIAssets _aiAssets;
        public AIAssets AIAssets
        {
            get
            {
                if (Connected && _aiAssets == null)
                    _aiAssets = new AIAssets(ASTServer, _httpClient);

                return _aiAssets;
            }
        }

        private AISupplyChainGlobalInventory _aiSupplyChainGlobalInventory;
        public AISupplyChainGlobalInventory AISupplyChainGlobalInventory
        {
            get
            {
                if (Connected && _aiSupplyChainGlobalInventory == null)
                    _aiSupplyChainGlobalInventory = new AISupplyChainGlobalInventory(ASTServer, _httpClient);

                return _aiSupplyChainGlobalInventory;
            }
        }

        private AISupplyChainScanResults _aiSupplyChainScanResults;
        public AISupplyChainScanResults AISupplyChainScanResults
        {
            get
            {
                if (Connected && _aiSupplyChainScanResults == null)
                    _aiSupplyChainScanResults = new AISupplyChainScanResults(ASTServer, _httpClient);

                return _aiSupplyChainScanResults;
            }
        }

        private SASTResourceManagement _sastResourceManagement;
        public SASTResourceManagement SASTResourceManagement
        {
            get
            {
                if (Connected && _sastResourceManagement == null)
                    _sastResourceManagement = new SASTResourceManagement(ASTServer, _httpClient);

                return _sastResourceManagement;
            }
        }

        private RepositoryInsights _repositoryInsights;
        public RepositoryInsights RepositoryInsights
        {
            get
            {
                if (Connected && _repositoryInsights == null)
                    _repositoryInsights = new RepositoryInsights(ASTServer, _httpClient);

                return _repositoryInsights;
            }
        }

        private SASTResults _SASTResults;

        /// <summary>
        /// Engine SAST results
        /// </summary>
        public SASTResults SASTResults
        {
            get
            {
                if (Connected && _SASTResults == null)
                    _SASTResults = new SASTResults(ASTServer, _httpClient);

                return _SASTResults;
            }
        }


        private SASTResultsPredicates _SASTResultsPredicates;

        /// <summary>
        /// Engine SAST results Predicates
        /// </summary>
        public SASTResultsPredicates SASTResultsPredicates
        {
            get
            {
                if (Connected && _SASTResultsPredicates == null)
                    _SASTResultsPredicates = new SASTResultsPredicates(ASTServer, _httpClient);



                return _SASTResultsPredicates;
            }
        }

        private SASTScanResultsCompare _SASTScanResultsCompare;

        /// <summary>
        /// SAST Scan Results Compare
        /// </summary>
        public SASTScanResultsCompare SASTScanResultsCompare
        {
            get
            {
                if (Connected && _SASTScanResultsCompare == null)
                    _SASTScanResultsCompare = new SASTScanResultsCompare(ASTServer, _httpClient);

                return _SASTScanResultsCompare;
            }
        }


        private KicsResults _kicsResults;

        /// <summary>
        /// KICS results
        /// </summary>
        public KicsResults KicsResults
        {
            get
            {
                if (Connected && _kicsResults == null)
                    _kicsResults = new KicsResults($"{ASTServer.AbsoluteUri}api/kics-results", _httpClient);



                return _kicsResults;
            }
        }

        private KICSResultsPredicates _kicsResultsPredicates;

        /// <summary>
        /// KICS marking/predicates
        /// </summary>
        public KICSResultsPredicates KicsResultsPredicates
        {
            get
            {
                if (Connected && _kicsResultsPredicates == null)
                    _kicsResultsPredicates = new KICSResultsPredicates(ASTServer, _httpClient);



                return _kicsResultsPredicates;
            }
        }

        private CxOneSCA _cxOneSCA;

        /// <summary>
        /// SCA API
        /// </summary>
        public CxOneSCA SCA
        {
            get
            {
                if (Connected && _cxOneSCA == null)
                    _cxOneSCA = new CxOneSCA(ASTServer, _httpClient);

                return _cxOneSCA;
            }
        }

        private ScannersResults _scannersResults;

        /// <summary>
        /// Engine Scanners results
        /// </summary>
        public ScannersResults ScannersResults
        {
            get
            {
                if (Connected && _scannersResults == null)
                    _scannersResults = new ScannersResults($"{ASTServer.AbsoluteUri}api/results", _httpClient);



                return _scannersResults;
            }
        }


        private ResultsSummary _resultsSummary;

        /// <summary>
        /// Engine Results Summary
        /// </summary>
        public ResultsSummary ResultsSummary
        {
            get
            {
                if (Connected && _resultsSummary == null)
                    _resultsSummary = new ResultsSummary($"{ASTServer.AbsoluteUri}api/scan-summary", _httpClient);

                return _resultsSummary;
            }
        }

        private ResultsOverview _resultsOverview;
        public ResultsOverview ResultsOverview
        {
            get
            {
                if (Connected && _resultsOverview == null)
                    _resultsOverview = new ResultsOverview($"{ASTServer.AbsoluteUri}api/results-overview", _httpClient);



                return _resultsOverview;
            }
        }


        private Configuration _configuration;

        /// <summary>
        /// Configurations
        /// </summary>
        public Configuration Configuration
        {
            get
            {
                if (Connected && _configuration == null)
                    _configuration = new Configuration($"{ASTServer.AbsoluteUri}api/configuration", _httpClient);

                return _configuration;
            }
        }

        private Repostore _repostore;

        public Repostore Repostore
        {
            get
            {
                if (Connected && _repostore == null)
                    _repostore = new Repostore($"{ASTServer.AbsoluteUri}api/repostore", _httpClient);

                return _repostore;
            }
        }

        private Uploads _uploads;

        public Uploads Uploads
        {
            get
            {
                if (Connected && _uploads == null)
                    _uploads = new Uploads($"{ASTServer.AbsoluteUri}api/uploads", _httpClient);



                return _uploads;
            }
        }

        private PresetManagement _presetManagement;

        public PresetManagement PresetManagement
        {
            get
            {
                if (Connected && _presetManagement == null)
                    _presetManagement = new PresetManagement($"{ASTServer.AbsoluteUri}api/preset-manager", _httpClient);

                return _presetManagement;
            }
        }

        private SastQueriesAuditPresets _auditPresetManagement;

        public SastQueriesAuditPresets AuditPresetManagement
        {
            get
            {
                if (Connected && _auditPresetManagement == null)
                    _auditPresetManagement = new SastQueriesAuditPresets($"{ASTServer.AbsoluteUri}api/presets", _httpClient);

                return _auditPresetManagement;
            }
        }

        private SASTQueriesAudit _sastQueriesAudit;

        public SASTQueriesAudit SASTQueriesAudit
        {
            get
            {
                if (Connected && _sastQueriesAudit == null)
                    _sastQueriesAudit = new SASTQueriesAudit($"{ASTServer.AbsoluteUri}api/cx-audit", _httpClient);

                return _sastQueriesAudit;
            }
        }

        // Session-based query CRUD lives in QueryEditorClient (Services/QueryEditorClient.cs) — it owns
        // the query editor service client itself, along with the session lifecycle and its own retry
        // policy. Lazily constructed the same way the other per-service properties above are, since it
        // needs _httpClient (only available once this instance exists).
        private QueryEditorClient _queryEditorClient;
        private QueryEditorClient queryEditorClient => _queryEditorClient ??= new QueryEditorClient(this, _httpClient);

        private Webhooks _webhooks;
        public Webhooks Webhooks
        {
            get
            {
                if (Connected && _webhooks == null)
                    _webhooks = new Webhooks($"{ASTServer.AbsoluteUri}api/webhooks", _httpClient);

                return _webhooks;
            }
        }

        #endregion

        #region Connection

        private int _bearerExpiresIn;
        private DateTime _bearerValidTo;
        private IReadOnlyList<string> _userPermissions;

        public bool Connected
        {
            get
            {
                if (_httpClient == null || (_bearerValidTo - DateTime.UtcNow).TotalMinutes < 5)
                {
                    var token = authenticate();
                    _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
                    _httpClient.DefaultRequestHeaders.ConnectionClose = false; // Explicitly ask to keep connection alive
                    _bearerValidTo = DateTime.UtcNow.AddSeconds(_bearerExpiresIn - 300);
                    _userPermissions = null; // invalidate on token refresh
                }
                return true;
            }
        }

        /// <summary>
        /// The list of CxOne permissions (roles_ast) granted to the authenticated user.
        /// Populated from the JWT token on first access and invalidated on token refresh.
        /// </summary>
        public IReadOnlyList<string> UserPermissions
        {
            get
            {
                if (_userPermissions == null)
                {
                    if (!Connected)
                        throw new Exception("Not connected to AST Server. Please authenticate first.");

                    var claims = JwtUtils.GetTokenClaims(_httpClient.DefaultRequestHeaders.Authorization?.Parameter);
                    _userPermissions = claims != null && claims.ContainsKey("roles_ast")
                        ? claims["roles_ast"].AsReadOnly()
                        : new List<string>().AsReadOnly();
                }
                return _userPermissions;
            }
        }

        public HttpClient HttpClient
        {
            get
            {
                if (!Connected)
                    throw new Exception("Not connected to AST Server. Please authenticate first.");
                return _httpClient;
            }
        }

        public string authenticate()
        {
            var response = requestAuthenticationToken();
            if (response.StatusCode == System.Net.HttpStatusCode.OK)
            {
                JObject accessToken = JsonConvert.DeserializeObject<JObject>(response.Content.ReadAsStringAsync().Result);
                string authToken = ((JProperty)accessToken.First).Value.ToString();
                _bearerExpiresIn = (int)accessToken["expires_in"];
                return authToken;
            }
            throw new Exception(response.Content.ReadAsStringAsync().Result);
        }

        public HttpResponseMessage TestConnection()
        {
            return requestAuthenticationToken();
        }

        private HttpResponseMessage requestAuthenticationToken()
        {
            var identityURL = $"{AccessControlServer.AbsoluteUri}auth/realms/{Tenant}/protocol/openid-connect/token";

            Dictionary<string, string> kv;

            if (!string.IsNullOrWhiteSpace(KeyApi))
            {
                kv = new Dictionary<string, string>
                {
                    { "grant_type", "refresh_token" },
                    { "client_id", "ast-app" },
                    { "refresh_token", $"{KeyApi}" }
                };
            }
            else
            {
                kv = new Dictionary<string, string>
                {
                    { "grant_type", "client_credentials" },
                    { "client_id", $"{ClientId}" },
                    { "client_secret", $"{ClientSecret}" }
                };
            }

            var req = new HttpRequestMessage(HttpMethod.Post, identityURL) { Content = new FormUrlEncodedContent(kv) };
            req.Headers.UserAgent.Add(new ProductInfoHeaderValue("ASAProgramTracker", "1.0"));

            _httpClient.DefaultRequestHeaders.Add("Accept", "*/*");
            return _httpClient.SendAsync(req).Result;
        }

        #endregion

        #region Client

        public ASTClient(CxOneConnection connectionSettings)
            : this(connectionSettings.CxOneServer, connectionSettings.AccessControlServer, connectionSettings.Tenant, connectionSettings.ApiKey) { }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="astServer">
        /// US Environment - https://ast.checkmarx.net/
        /// EU Environment - https://eu.ast.checkmarx.net/
        /// </param>
        /// <param name="server">
        /// URL
        /// https://eu.iam.checkmarx.net
        /// https://iam.checkmarx.net
        /// </param>
        /// <param name="tenant"></param>
        /// <param name="apiKey"></param>
        /// <exception cref="ArgumentNullException"></exception>
        public ASTClient(Uri astServer, Uri accessControlServer, string tenant, string apiKey)
        {
            if (astServer == null) throw new ArgumentNullException(nameof(astServer));
            if (accessControlServer == null) throw new ArgumentNullException(nameof(accessControlServer));
            if (string.IsNullOrWhiteSpace(tenant)) throw new ArgumentNullException(nameof(tenant));
            if (string.IsNullOrWhiteSpace(apiKey)) throw new ArgumentNullException(nameof(apiKey));

            ASTServer = astServer;
            AccessControlServer = accessControlServer;
            Tenant = tenant;
            KeyApi = apiKey;

        }

        public ASTClient(Uri astServer, Uri accessControlServer, string tenant, string clientId, string clientSecret)
        {
            if (astServer == null) throw new ArgumentNullException(nameof(astServer));
            if (accessControlServer == null) throw new ArgumentNullException(nameof(accessControlServer));
            if (string.IsNullOrWhiteSpace(tenant)) throw new ArgumentNullException(nameof(tenant));
            if (string.IsNullOrWhiteSpace(clientId)) throw new ArgumentNullException(nameof(clientId));
            if (string.IsNullOrWhiteSpace(clientSecret)) throw new ArgumentNullException(nameof(clientSecret));

            ASTServer = astServer;
            AccessControlServer = accessControlServer;
            Tenant = tenant;
            ClientId = clientId;
            ClientSecret = clientSecret;
        }

        #endregion

        #region User

        private UserModel _user = null;
        public UserModel User
        {
            get
            {
                if (_user == null)
                {
                    if (!Connected)
                        throw new Exception("Not connected to AST Server. Please authenticate first.");

                    _user = new UserModel();

                    var claims = JwtUtils.GetTokenClaims(_httpClient.DefaultRequestHeaders.Authorization?.Parameter);

                    if (claims.ContainsKey("name"))
                        _user.Name = claims["name"].Single();

                    if (claims.ContainsKey("email"))
                        _user.Email = claims["email"].Single();
                }

                return _user;
            }
        }

        #endregion

        #region License Details

        private LicenseDto _licenseDetails = null;
        public LicenseDto LicenseDetails
        {
            get
            {
                if (_licenseDetails == null)
                {
                    if (!Connected)
                        throw new Exception("Not connected to AST Server. Please authenticate first.");

                    var claims = JwtUtils.GetTokenClaims(_httpClient.DefaultRequestHeaders.Authorization?.Parameter);
                    if (claims.ContainsKey(Claim_License))
                    {
                        var licensesJson = claims[Claim_License].Single();
                        _licenseDetails = JsonConvert.DeserializeObject<LicenseDto>(licensesJson);
                    }
                }

                return _licenseDetails;
            }
        }

        private IEnumerable<LicenseEngineTypeEnum> _allowedEngines = null;
        public IEnumerable<LicenseEngineTypeEnum> AllowedEngines
        {
            get
            {
                if (_allowedEngines == null)
                {
                    var engineStrings = LicenseDetails.LicenseData?.AllowedEngines;
                    if (engineStrings == null)
                        _allowedEngines = Enumerable.Empty<LicenseEngineTypeEnum>();
                    else
                        _allowedEngines = engineStrings
                            .Select(EnumUtils.GetEnumValueByDescription<LicenseEngineTypeEnum>)
                            .ToList();
                }

                return _allowedEngines;
            }
        }

        #endregion

        #region Applications

        // TODO: When this cache should be invalidated
        private Services.Applications.ApplicationsCollection _apps { get; set; }
        public Services.Applications.ApplicationsCollection Apps
        {
            get
            {
                if (_apps == null)
                    _apps = getAllApplications();

                return _apps;
            }
            set
            {
                _apps = value;
            }
        }

        private Services.Applications.ApplicationsCollection getAllApplications(int limit = 20)
        {
            var listApplications = Applications.GetListOfApplicationsAsync(limit).Result;
            if (listApplications.TotalCount > limit)
            {
                var offset = limit;
                bool cont = true;
                do
                {
                    var next = Applications.GetListOfApplicationsAsync(limit, offset).Result;
                    if (next.Applications.Any())
                    {
                        next.Applications.ToList().ForEach(o => listApplications.Applications.Add(o));
                        offset += limit;

                        if (listApplications.Applications.Count == listApplications.TotalCount) cont = false;
                    }
                    else
                        cont = false;

                } while (cont);
            }

            return listApplications;
        }

        public IEnumerable<Services.Applications.Application> GetProjectApplications(Guid projectId)
        {
            return Apps.Applications?.Where(x => x.ProjectIds != null && x.ProjectIds.Contains(projectId));
        }

        public Services.Applications.Application GetProjectApplication(Guid projectId)
        {
            return GetProjectApplications(projectId)?.FirstOrDefault();
        }

        // Invalidate via InvalidateApplicationGroupNamesCache when:
        //   - AccessManagement.CreateAssignmentAsync  (group assigned to an application)
        //   - AccessManagement.DeleteAssignmentAsync  (group removed from an application)
        //   - AccessManagement.CreateMultipleAssignmentsAsync (bulk group-application assignments)
        private ConcurrentDictionary<Guid, IEnumerable<string>> _applicationGroupNames = new();

        public IEnumerable<string> GetApplicationGroupNames(Guid applicationId)
        {
            return _applicationGroupNames.GetOrAdd(applicationId, id =>
            {
                var assignments = AccessManagement.GetEntitiesForAsync(
                    id.ToString(),
                    "application",
                    "group",
                    System.Threading.CancellationToken.None).Result;

                return assignments?
                    .Where(a => a.EntityType == AssignmentEntityType.Group)
                    .Select(a => a.EntityName)
                    .ToList()
                    ?? new List<string>();
            });
        }

        public void InvalidateApplicationGroupNamesCache(Guid? applicationId = null)
        {
            if (applicationId.HasValue)
                _applicationGroupNames.TryRemove(applicationId.Value, out _);
            else
                _applicationGroupNames = new();
        }

        #endregion

        #region Audit

        /// <summary>
        /// Retrieves all audit events for the given date range, including events stored in
        /// the daily archive links returned by the API.
        /// </summary>
        /// <param name="from">Start date in YYYY-MM-DD format. Cannot be more than 365 days in the past.</param>
        /// <param name="to">End date in YYYY-MM-DD format.</param>
        /// <returns>Combined list of all audit events from both the inline response and every archive link.</returns>
        public IList<Services.Audit.AuditEvent> GetAllAuditEvents(DateTime from, DateTime to)
        {
            var result = Audit.GetAuditEventsAsync(from, to).Result;
            var allEvents = new List<Services.Audit.AuditEvent>();

            if (result.Links != null)
            {
                foreach (var link in result.Links)
                {
                    if (string.IsNullOrEmpty(link.Url))
                        continue;

                    var json = Audit.DownloadLinkAsync(link.Url).Result;
                    if (!string.IsNullOrEmpty(json))
                    {
                        var events = JsonConvert.DeserializeObject<List<Services.Audit.AuditEvent>>(json);
                        if (events != null)
                            allEvents.AddRange(events);
                    }
                }
            }

            if (result.Events != null)
                allEvents.AddRange(result.Events);

            return allEvents;
        }

        public ICollection<Services.AuditEvent> GetAllAuditEventProcessor(DateTime? from = null, DateTime? to = null, int startAt = 0, int limit = 1000)
        {
            if (limit <= 0)
                throw new ArgumentOutOfRangeException(nameof(limit));

            var result = new List<Services.AuditEvent>();

            while (true)
            {
                var resultPage = AuditEventProcessor
                    .GetAllAsync(limit, startAt, from, to)
                    .GetAwaiter()
                    .GetResult();

                var events = resultPage.Events;

                if (events == null || events.Count == 0)
                    break;

                result.AddRange(events);

                if (events.Count < limit)
                    break;

                startAt += limit;
            }

            return result;
        }

        #endregion

        #region Feature Flags

        private IEnumerable<Flag> _allFeatureFlags = null;
        public IEnumerable<Flag> GetFeatureFlags()
        {
            if (_allFeatureFlags == null)
                _allFeatureFlags = FeatureFlags.GetFlagsAsync().Result;

            return _allFeatureFlags;
        }

        public Flag GetFeatureFlag(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentNullException(nameof(name));

            return GetFeatureFlags()?.SingleOrDefault(x => x.Name == name);
        }

        public bool AreCustomStatesEnabled
        {
            get
            {
                var customStatesFlag = GetFeatureFlag(Feature_Flag_CustomStatesEnabled);

                return customStatesFlag != null && customStatesFlag.Status;
            }
        }

        #endregion

        #region Custom States

        private IEnumerable<CustomState> _allCustomStates = null;
        public IEnumerable<CustomState> GetAllCustomStates()
        {
            if (!AreCustomStatesEnabled)
                throw new NotSupportedException($"Feature Flag {Feature_Flag_CustomStatesEnabled} is disabled.");

            if (_allCustomStates == null)
                _allCustomStates = CustomStates.GetAllAsync().Result;

            return _allCustomStates;
        }

        public CustomState GetCustomState(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentNullException(nameof(name));

            return GetAllCustomStates()?.SingleOrDefault(x => x.Name.Equals(name, StringComparison.InvariantCultureIgnoreCase));
        }

        public void CreateNewCustomState(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentNullException(nameof(name));

            if (GetCustomState(name) != null)
                throw new Exception($"There is already a custom state with the same name.");

            CustomStates.CreateAsync(new CustomStateCreateBody()
            {
                Name = name
            }).Wait();

            _allCustomStates = null;
        }

        public void DeleteCustomState(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentNullException(nameof(name));

            var customStateToDelete = GetCustomState(name);
            if (customStateToDelete == null)
                throw new Exception($"Custom state with name {name} not found.");

            CustomStates.DeleteAsync(customStateToDelete.Id.ToString())
                .GetAwaiter()
                .GetResult();

            _allCustomStates = null;
        }

        private List<SASTResultState> _sastStates = null;
        public List<SASTResultState> SASTStates
        {
            get
            {
                if (_sastStates == null)
                {
                    _sastStates = EnumUtils.GetStateEnumMemberList<ResultsState>().OfType<SASTResultState>().ToList();
                    addCustomStatesIfNeeded(_sastStates);
                }

                return _sastStates;
            }
        }

        private List<SCAResultState> _scaStates = null;
        public List<SCAResultState> SCAStates
        {
            get
            {
                if (_scaStates == null)
                {
                    _scaStates = EnumUtils.GetStateEnumMemberList<ScaVulnerabilityStatus>().OfType<SCAResultState>().ToList();
                    addCustomStatesIfNeeded(_scaStates);
                }

                return _scaStates;
            }
        }

        private List<KicsResultState> _kicsStates = null;
        public List<KicsResultState> KicsStates
        {
            get
            {
                if (_kicsStates == null)
                {
                    _kicsStates = EnumUtils.GetStateEnumMemberList<KicsStateEnum>().OfType<KicsResultState>().ToList();
                    addCustomStatesIfNeeded(_kicsStates);
                }

                return _kicsStates;
            }
        }

        private void addCustomStatesIfNeeded<TState>(List<TState> states) where TState : ResultState, new()
        {
            if (!AreCustomStatesEnabled)
                return;

            var customStates = GetAllCustomStates();

            if (!customStates.Any())
                return;

            foreach (var state in customStates)
            {
                states.Add(new TState
                {
                    Id = state.Id,
                    Name = state.Name
                });
            }
        }

        #endregion

        #region Projects

        public ICollection<Services.Projects.Project> GetAllProjectsDetails(int startAt = 0, int limit = 500)
        {
            if (limit <= 0)
                throw new ArgumentOutOfRangeException(nameof(limit));

            var result = new List<Services.Projects.Project>();

            while (true)
            {
                var resultPage = Projects.GetListOfProjectsAsync(limit: limit, offset: startAt).Result;

                if (resultPage.Projects != null)
                    result.AddRange(resultPage.Projects);

                startAt += limit;

                if (resultPage.TotalCount == 0 || resultPage.TotalCount == result.Count)
                    return result;
            }
        }

        public IEnumerable<Risk> GetApiRisks(Guid scan_id)
        {
            var result = new List<Risk>();
            int? pageNumber = null;

            while (true)
            {
                var resultPage = API_Risks.ApiRisksAsync(scan_id, page: pageNumber).Result;

                if (resultPage != null)
                    result.AddRange(resultPage.Entries);

                pageNumber = resultPage.Next_page_number;

                if (!resultPage.Has_next)
                    return result;
            }
        }

        public RichProject GetProject(Guid id)
        {
            if (id == Guid.Empty)
                throw new ArgumentNullException(nameof(id));

            return Projects.GetProjectAsync(id).Result;
        }

        public void UpdateProjectTags(Guid projectId, IDictionary<string, string> tags)
        {
            if (tags == null)
                throw new ArgumentNullException(nameof(tags));

            var project = Projects.GetProjectAsync(projectId).Result;
            if (project == null)
                throw new Exception($"No project found with id {projectId}");

            var groups = project.Groups != null && project.Groups.Any() ? project.Groups : null;

            // Trying to update RepoUrl on a imported project will result in a 400 Bad Request error "cannot update repo_url for an imported project"
            // Removed from input body to avoid this error. It will not change the value of RepoUrl if it is not included in the request body.
            ProjectInput input = new ProjectInput
            {
                Tags = tags,
                Name = project.Name,
                Groups = groups,
                //RepoUrl = project.RepoUrl,
                MainBranch = project.MainBranch,
                Origin = project.Origin,
                AdditionalProperties = project.AdditionalProperties
            };

            Projects.UpdateProjectAsync(projectId, input).Wait();
        }

        public IEnumerable<string> GetProjectBranches(Guid projectId, int startAt = 0, int limit = 500)
        {
            if (startAt < 0)
                throw new ArgumentOutOfRangeException(nameof(startAt));

            if (limit <= 0)
                throw new ArgumentOutOfRangeException(nameof(limit));

            while (true)
            {
                var response = Projects.BranchesAsync(projectId, startAt, limit).Result;
                foreach (var result in response)
                {
                    yield return result;
                }

                if (response.Count() < limit)
                    yield break;

                startAt += limit;
            }
        }

        public IEnumerable<KicsResult> GetKicsScanResultsById(Guid scanId, int startAt = 0, int limit = 500)
        {
            if (startAt < 0)
                throw new ArgumentOutOfRangeException(nameof(startAt));

            if (limit <= 0)
                throw new ArgumentOutOfRangeException(nameof(limit));

            while (true)
            {
                var response = KicsResults.GetKICSResultsByScanAsync(scanId, startAt, limit).Result;
                foreach (var result in response.Results)
                {
                    yield return result;
                }

                if (response.Results.Count() < limit)
                    yield break;

                startAt += limit;
            }
        }

        /// <summary>
        /// For SCA it just returns the vulnerabilities.
        /// </summary>
        /// <param name="scanId">Id of the scan</param>
        /// <param name="engines"></param>
        /// <returns></returns>
        public IEnumerable<ScannerResult> GetScannersResultsById(Guid scanId, System.Collections.Generic.IEnumerable<Checkmarx.API.AST.Services.ScannersResults.SeverityEnum> severities = null, params string[] engines)
        {
            if (scanId == Guid.Empty)
                throw new ArgumentNullException(nameof(scanId));

            int page = 0;
            int limit = 500;

            while (true)
            {
                var response = ScannersResults.GetResultsByScanAsync(scanId, page, limit, severity: severities).Result;
                foreach (var result in response.Results)
                {
                    if (!engines.Any() || (engines.Any() && engines.Contains(result.Type, StringComparer.InvariantCultureIgnoreCase)))
                        yield return result;
                }

                if (response.Results.Count() < limit)
                    yield break;

                page++;
            }
        }

        public IEnumerable<ResultsSummary> GetResultsSummaryById(Guid scanId)
        {
            return ResultsSummary.SummaryByScansIdsAsync(new Guid[] { scanId }, include_files: false,
               include_queries: false,
               include_severity_status: true,
               include_status_counters: false).Result.ScansSummaries;
        }

        public Checkmarx.API.AST.Services.Projects.Project CreateProject(string name, Dictionary<string, string> tags)
        {
            return Projects.CreateProjectAsync(new ProjectInput()
            {
                Name = name,
                Tags = tags
            }).Result;
        }

        public static Uri GetProjectUri(Uri astServer, Guid projectId)
        {
            if (astServer == null)
                throw new ArgumentNullException(nameof(astServer));

            if (projectId == Guid.Empty)
                throw new ArgumentException("Empty is not a valid project Id");

            return new Uri(astServer, $"projects/{projectId.ToString("D")}/overview");
        }

        public Dictionary<string, SubsetScan> GetProjectsLastScans(IEnumerable<Guid> projectIds = null, bool completed = true, ScanTypeEnum scanType = ScanTypeEnum.sast, int startAt = 0, int limit = 500)
        {
            if (limit <= 0)
                throw new ArgumentOutOfRangeException(nameof(limit));

            var scanStatus = completed ? CompletedStage : null;

            var result = new Dictionary<string, SubsetScan>();

            while (true)
            {
                // Fetch the page of results
                var resultPage = Projects.GetProjectLastScan(projectIds, engine: scanType.ToString(), scan_status: scanStatus, limit: limit, offset: startAt).Result;

                // Add each item individually to avoid duplicates
                foreach (var kvp in resultPage)
                {
                    // Optional: skip if key already exists
                    if (!result.ContainsKey(kvp.Key))
                        result.Add(kvp.Key, kvp.Value);
                }

                startAt += limit;

                // Stop if no more items returned
                if (resultPage.Count == 0)
                    break;
            }

            return result;
        }

        #endregion

        #region Scans

        #region Source Code 

        public byte[] GetSourceCode(Guid scanId)
        {
            if (scanId == Guid.Empty)
                throw new ArgumentNullException(nameof(scanId));

            var fileResponse = Repostore.CodeAsync(scanId).Result;

            byte[] result = null;
            byte[] buffer = new byte[4096];

            using (Stream dataStream = fileResponse.Stream)
            {
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    int count = 0;
                    do
                    {
                        count = dataStream.Read(buffer, 0, buffer.Length);
                        memoryStream.Write(buffer, 0, count);
                    } while (count != 0);
                    result = memoryStream.ToArray();
                }
            }

            return result;
        }

        /// <summary>
        /// Exports the source code to a zip file defined by the file path
        /// </summary>
        /// <param name="scanId"></param>
        /// <param name="filePath"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        public string GetSourceCode(Guid scanId, string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath))
                throw new ArgumentNullException(nameof(filePath));

            System.IO.File.WriteAllBytes(filePath, GetSourceCode(scanId));

            return Path.GetFullPath(filePath);
        }

        #endregion

        /// <summary>
        /// Get all completed scans from project
        /// </summary>
        /// <param name="projectId"></param>
        /// <returns></returns>
        public IEnumerable<Scan> GetAllScans(Guid projectId, string branch = null, bool completed = true, DateTime? minScanDate = null)
        {
            return GetScans(projectId, branch: branch, completed: completed, minScanDate: minScanDate);
        }

        private IEnumerable<Scan> getAllScans(Guid projectId, string branch = null, int itemsPerPage = 1000, int startAt = 0, IEnumerable<string> tagKeys = null)
        {
            while (true)
            {
                var result = Scans.GetListOfScansAsync(projectId, limit: itemsPerPage, offset: startAt, branch: branch, tags_keys: tagKeys).Result;

                foreach (var scan in result.Scans)
                {
                    yield return scan;
                }

                startAt += itemsPerPage;

                if (result.Scans.Count == 0)
                    yield break;
            }
        }

        public IEnumerable<Scan> SearchScans(string initiator = null, string tagKey = null, string[] sourceOrigin = null, int itemsPerPage = 1000, int startAt = 0, DateTimeOffset? fromDate = null, IEnumerable<string> scan_ids = null, IEnumerable<Status> statuses = null)
        {
            string[] tagKeys = null;
            if (!string.IsNullOrWhiteSpace(tagKey))
                tagKeys = [tagKey];

            string[] initiators = null;
            if (!string.IsNullOrWhiteSpace(initiator))
                initiators = [initiator];

            while (true)
            {
                var result = Scans.GetListOfScansAsync(limit: itemsPerPage, offset: startAt, initiators: initiators, tags_keys: tagKeys, source_origins: sourceOrigin, from_date: fromDate, scan_ids: scan_ids, statuses: statuses).Result;

                foreach (var scan in result.Scans)
                {
                    yield return scan;
                }

                startAt += itemsPerPage;

                if (result.Scans.Count == 0)
                    yield break;
            }
        }

        public Scan GetLastScan(Guid projectId, bool fullScanOnly = false, bool completed = true, string branch = null, ScanTypeEnum scanType = ScanTypeEnum.sast, DateTime? maxScanDate = null, string engineVersion = null)
        {
            if (!fullScanOnly && !maxScanDate.HasValue && string.IsNullOrWhiteSpace(engineVersion))
            {
                var scanStatus = completed ? CompletedStage : null;

                var scans = this.Projects.GetProjectLastScan([projectId], scan_status: scanStatus, branch: branch, engine: scanType.ToString()).Result;

                if (scans.ContainsKey(projectId.ToString()))
                    return this.Scans.GetScanAsync(scans[projectId.ToString()].Id).Result;

                return null;
            }
            else
            {
                var scans = GetScans(projectId, scanType.ToString(), completed, branch, ScanRetrieveKind.All, maxScanDate, sastEngineVersion: engineVersion);
                if (fullScanOnly)
                {
                    var fullScans = scans.Where(x => !IsScanIncremental(x.Id)).OrderByDescending(x => x.CreatedAt);

                    if (fullScans.Any())
                        return fullScans.FirstOrDefault();
                    else
                        return scans.OrderByDescending(x => x.CreatedAt).FirstOrDefault();
                }
                else
                    return scans.FirstOrDefault();
            }
        }

        public Scan GetFirstScan(Guid projectId, bool fullScanOnly = false, bool completed = true, string branch = null, ScanTypeEnum? scanType = null, DateTime? minScanDate = null)
        {
            var scans = GetScans(projectId, scanType?.ToString(), completed, branch, ScanRetrieveKind.All, minScanDate: minScanDate).OrderBy(x => x.CreatedAt);

            if (!fullScanOnly)
            {
                return scans.FirstOrDefault();
            }
            else
            {
                var fullScans = scans.Where(x => IsScanIncremental(x.Id)).OrderBy(x => x.CreatedAt);

                if (fullScans.Any())
                    return fullScans.FirstOrDefault();
                else
                    return scans.FirstOrDefault();
            }
        }

        /// <summary>
        /// Get first locked Scan
        /// </summary>
        /// <param name="projectId"></param>
        /// <returns></returns>
        public Scan GetLockedSASTScan(Guid projectId, string branch = null)
        {
            return GetScans(projectId, SAST_Engine, true, branch, ScanRetrieveKind.Locked).FirstOrDefault();
        }

        private ConcurrentDictionary<Guid, ScanInfo> _sastScansMetada = new ConcurrentDictionary<Guid, ScanInfo>();

        /// <summary>
        /// Get list of scans, filtered by engine, completion  and scankind
        /// </summary>
        /// <param name="projectId">Project Id</param>
        /// <param name="engine">Engine</param>
        /// <param name="completed">Retrieves only completed scans</param>
        /// <param name="scanKind">All scans or only the first or last </param>
        /// <param name="maxScanDate">Max scan date, including the date</param>
        /// <param name="minScanDate">Min scan date, including the date</param>
        /// <returns></returns>
        public IEnumerable<Scan> GetScans(Guid projectId,
            string engine = null,
            bool completed = true,
            string branch = null, ScanRetrieveKind scanKind = ScanRetrieveKind.All,
            DateTime? maxScanDate = null,
            DateTime? minScanDate = null,
            IEnumerable<string> tagKeys = null,
            string sastEngineVersion = null)
        {
            var scans = getAllScans(projectId, branch, tagKeys: tagKeys);

            List<Scan> list = [];
            if (scans.Any())
            {
                scans = scans.Where(x =>
                    (!completed || x.Status == Status.Completed || x.Status == Status.Partial) &&
                    (string.IsNullOrEmpty(branch) || x.Branch == branch) &&
                    (maxScanDate == null || x.CreatedAt.DateTime <= maxScanDate) &&
                    (minScanDate == null || x.CreatedAt.DateTime >= minScanDate)
                );

                if (engine == null || engine == SAST_Engine)
                    loadSASTMetadataInfoForScans(scans.Select(x => x.Id).ToArray());

                switch (scanKind)
                {
                    case ScanRetrieveKind.First:
                        scans = scans.Skip(Math.Max(0, scans.Count() - 1));
                        break;
                    case ScanRetrieveKind.Last:
                        scans = scans.Take(1);
                        break;
                    case ScanRetrieveKind.All:
                        break;
                }

                foreach (var scan in scans)
                {
                    if (!string.IsNullOrEmpty(engine))
                    {
                        if (scan.Engines != null && scan.Engines.Any(x => x == engine &&
                            (scan.Status == Status.Completed || scan.StatusDetails?.SingleOrDefault(x => x.Name == engine)?.Status == CompletedStage)))
                        {
                            list.Add(scan);
                        }
                    }
                    else
                    {
                        list.Add(scan);
                    }
                }

                if (list.Any() && !string.IsNullOrEmpty(sastEngineVersion))
                {
                    var scanIds = list.Where(x => x.Engines != null && x.Engines.Any(e => e.Equals(SAST_Engine, StringComparison.InvariantCultureIgnoreCase))).Select(x => x.Id);

                    var scansWithinVersion = GetScanEngineVersionAsync(scanIds).Result.Where(x => x.Value != null && x.Value.StartsWith(sastEngineVersion)).Select(x => x.Key).ToHashSet();

                    return list.Where(x => scansWithinVersion.Contains(x.Id));
                }
            }

            return list;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="projectId"></param>
        /// <param name="scanId"></param>
        /// <returns></returns>
        public ScanDetails GetScanDetails(Guid scanId)
        {
            return GetScanDetails(Scans.GetScanAsync(scanId).Result);
        }

        public ScanDetails GetScanDetails(Scan scan)
        {
            if (scan == null)
                throw new ArgumentNullException($"No scan found.");

            return new ScanDetails(this, scan);
        }

        public ReportResults GetCxOneScanJsonReport(Guid projectId, Guid scanId, double secondsBetweenPolls = 0.5)
        {
            TimeSpan poolInverval = TimeSpan.FromSeconds(secondsBetweenPolls);

            ScanReportCreateInput sc = new ScanReportCreateInput
            {
                ReportName = BaseReportCreateInputReportName.ScanReport,
                ReportType = BaseReportCreateInputReportType.Ui,
                FileFormat = BaseReportCreateInputFileFormat.Json,
                Data = new Data
                {
                    ProjectId = projectId,
                    ScanId = scanId
                }
            };

            ReportCreateOutput createReportOutut = Reports.CreateReportAsync(sc).Result;

            if (createReportOutut == null)
                throw new NotSupportedException();

            var createReportId = createReportOutut.ReportId;

            if (createReportId == Guid.Empty)
                throw new Exception($"Error getting Report of Scan {scanId}");

            Guid reportId = createReportId;
            string reportStatus = "Requested";
            string pastReportStatus = reportStatus;
            double aprox_seconds_passed = 0.0;
            Report statusResponse = null;

            do
            {
                System.Threading.Thread.Sleep(poolInverval);
                aprox_seconds_passed += 1.020;

                statusResponse = Reports.GetReportAsync(reportId, true).Result;
                reportId = statusResponse.ReportId;
                reportStatus = statusResponse.Status.ToString();

                if (pastReportStatus != reportStatus)
                {
                    pastReportStatus = reportStatus;
                }

                if (aprox_seconds_passed > 60)
                {
                    throw new TimeoutException("AST Scan json report for project {0} is taking a long time! Try again later.");
                }

                if (reportStatus == "Failed")
                {

                    throw new Exception("AST Scan API says it could not generate a json report for project {0}. You may want to try again later.");
                }

            } while (reportStatus != "Completed");

            var reportString = Reports.DownloadScanReportJsonUrl(statusResponse.Url).Result;

            return JsonConvert.DeserializeObject<ReportResults>(reportString);
        }

        public IEnumerable<SASTResult> GetSASTScanResultsById(Guid scanId, int startAt = 0, int limit = 500)
        {
            if (startAt < 0)
                throw new ArgumentOutOfRangeException(nameof(startAt));

            if (limit <= 0)
                throw new ArgumentOutOfRangeException(nameof(limit));


            while (true)
            {
                Services.SASTResults.SASTResultsResponse response = SASTResults.GetSASTResultsByScanAsync(scanId, startAt, limit).Result;

                if (response.Results != null)
                {
                    foreach (var result in response.Results)
                    {
                        yield return result;
                    }

                    if (response.Results.Count() < limit)
                        yield break;

                    startAt += limit;
                }
                else
                {
                    yield break;
                }
            }
        }

        public IEnumerable<SastResultCompare> GetSASTScanCompareResultsByScans(Guid baseScanId, Guid scanId, int startAt = 0, int limit = 500)
        {
            if (startAt < 0)
                throw new ArgumentOutOfRangeException(nameof(startAt));

            if (limit <= 0)
                throw new ArgumentOutOfRangeException(nameof(limit));

            while (true)
            {
                SastResultCompareResponse response = SASTResults.GetSASTResultsCompareByScansAsync(baseScanId, scanId, offset: startAt, limit: limit).Result;

                if (response.Results != null)
                {
                    foreach (var result in response.Results)
                    {
                        yield return result;
                    }

                    if (response.Results.Count() < limit)
                        yield break;

                    startAt += limit;
                }
                else
                {
                    yield break;
                }
            }
        }

        public List<Vulnerability> GetScaScanVulnerabilities(Guid scanId, List<ScaVulnerability> scaRisks = null)
        {
            var vulnerabilities = Requests.GetScanReport(scanId).Vulnerabilities;

            // Check if there are uncommitted changes
            if (SCAScanHasVulnerabilityChanges(scanId))
            {
                var risks = scaRisks ?? GraphQLClient.GetAllVulnerabilitiesRisksByScanIdAsync(new VulnerabilitiesRisksByScanIdVariables
                {
                    ScanId = scanId
                }).Result;

                // Scan report brings only committed changes, so we need to update with pending changes if any
                foreach (var risk in risks.Where(x => x.PendingChanges))
                {
                    var _vuln = vulnerabilities.Single(x => x.Match(risk));

                    if (_vuln.Score != risk.PendingScore)
                        _vuln.Score = risk.PendingScore;

                    if (_vuln.RiskState != risk.PendingState)
                        _vuln.RiskState = risk.PendingState;

                    if (_vuln.Severity != risk.PendingSeverity)
                        _vuln.Severity = risk.PendingSeverity;
                }
            }

            return vulnerabilities;
        }

        public bool SCAScanHasVulnerabilityChanges(Guid scanId)
        {
            return GraphQLClient.GetSCAScanLatestChanges(scanId).HasVulnerabilityChanges;
        }

        #region ReRun Scans

        public Scan ReRunGitScan(Guid projectId, string repoUrl, IEnumerable<ConfigType> scanTypes, string branch, string preset,
                string configuration = null,
                bool incremental = false,
                Dictionary<string, string> tags = null,
                bool enableFastScan = false)
        {
            ScanInput scanInput = new()
            {
                Project = new Services.Scans.Project()
                {
                    Id = projectId
                },
                Type = ScanInputType.Git,
                Handler = new Git()
                {
                    Branch = branch,
                    RepoUrl = repoUrl
                },
                Config = createScanConfigForAllEngines(scanTypes, preset, configuration, incremental, enableFastScan: enableFastScan)
            };

            if (tags != null)
                scanInput.Tags = tags;

            return Scans.CreateScanAsync(scanInput).Result;

        }

        public Scan ReRunUploadScan(Guid projectId, Guid lastScanId, IEnumerable<ConfigType> scanTypes, string branch, string preset, string configuration = null,
            Dictionary<string, string> tags = null,
            bool? enableFastScan = null)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentNullException(nameof(projectId));

            if (lastScanId == Guid.Empty)
                throw new ArgumentNullException(nameof(lastScanId));

            byte[] source = GetSourceCode(lastScanId);

            return RunUploadScan(projectId, source, scanTypes, branch, preset, configuration, tags: tags, enableFastScan: enableFastScan);
        }

        public Scan RunUploadScan(Guid projectId, byte[] source, IEnumerable<ConfigType> scanTypes, string branch, string preset,
            string configuration = null,
            Dictionary<string, string> tags = null,
            bool? enableFastScan = null)
        {
            if (source == null)
                throw new ArgumentNullException(nameof(source));

            if (scanTypes == null || !scanTypes.Any())
                throw new ArgumentNullException(nameof(scanTypes));

            string uploadUrl = Uploads.GetPresignedURLForUploading().Result;

            Uploads.SendHTTPRequestByFullURL(uploadUrl, source).Wait();

            ScanUploadInput scanInput = new()
            {
                Project = new Services.Scans.Project()
                {
                    Id = projectId
                },
                Type = ScanInputType.Upload,
                Handler = new Upload()
                {
                    Branch = branch,
                    UploadUrl = uploadUrl
                },
                Config = createScanConfigForAllEngines(scanTypes, preset, configuration, enableFastScan: enableFastScan)
            };

            if (tags != null)
                scanInput.Tags = tags;

            return Scans.CreateScanUploadAsync(scanInput).Result;

        }

        #endregion

        #region Scan Configuration

        private ICollection<Config> createScanConfigForAllEngines(IEnumerable<ConfigType> scanTypes, string preset, string configuration, bool incremental = false, bool? enableFastScan = null)
        {
            var configs = new List<Config>();

            foreach (var scanType in scanTypes)
            {
                var engineConfig = new Config { Type = scanType };

                switch (scanType)
                {
                    case ConfigType.Sca:
                        // engineConfig.Value = getSCAConfiguration();
                        break;
                    case ConfigType.Sast:
                        engineConfig.Value = getSASTScanConfiguration(preset, configuration, incremental, enableFastScan);
                        break;
                    case ConfigType.Kics:
                        // Swagger
                        break;
                    case ConfigType.Microengines:
                        break;
                    case ConfigType.ApiSec:
                        // Swagger File/Folders
                        break;
                    case ConfigType.System:
                        break;
                    default:
                        throw new NotSupportedException($"{scanType}");
                }

                configs.Add(engineConfig);
            }

            return configs;
        }

        private IDictionary<string, string> getSCAConfiguration(bool exploitablePath = false)
        {
            var result = new Dictionary<string, string>()
            {
                ["ExploitablePath"] = exploitablePath.ToString()
            };

            return result;
        }

        private IDictionary<string, string> getSASTScanConfiguration(string preset, string configuration, bool incremental, bool? enableFastScan = null, bool engineVerbose = false)
        {
            var result = new Dictionary<string, string>()
            {
                ["incremental"] = incremental.ToString(),
                ["presetName"] = preset,
                ["engineVerbose"] = engineVerbose.ToString()
            };

            if (!string.IsNullOrEmpty(configuration))
                result.Add("defaultConfig", configuration);

            if (enableFastScan != null)
            {
                result.Add("fastScanMode", enableFastScan.Value.ToString());

                if (enableFastScan.Value)
                    result.Add("languageMode", 5.ToString()); // force to 5...
            }

            return result;
        }

        #endregion

        public void DeleteScan(Guid scanId)
        {
            var scan = Scans.GetScanAsync(scanId).Result;
            if (scan != null)
            {
                if (scan.Status == Status.Running || scan.Status == Status.Queued)
                    CancelScan(scanId);

                Scans.DeleteScanAsync(scanId).Wait();
            }
        }

        public void CancelScan(Guid scanId)
        {
            Scans.CancelScanAsync(scanId, new Body { Status = Status.Canceled.ToString() }).Wait();
        }

        #endregion

        #region Results

        public bool MarkSASTResult(Guid projectId, SASTResult result, IEnumerable<PredicateWithCommentJSON> history, bool updateSeverity = true,
            bool updateState = true, bool updateComment = true, Guid? scanId = null)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentException(nameof(projectId));

            if (history == null)
                throw new NullReferenceException(nameof(history));

            if (result == null)
                throw new ArgumentNullException(nameof(result));

            List<PredicateBySimiliartyIdBody> body = [];

            foreach (var predicate in history)
            {
                PredicateBySimiliartyIdBody newBody = new PredicateBySimiliartyIdBody
                {
                    SimilarityId = predicate.SimilarityId.ToString(),
                    ProjectId = projectId,
                    ScanId = scanId,
                    Severity = updateSeverity ? predicate.Severity : result.Severity,
                    Comment = updateComment ? predicate.Comment : null
                };

                if (updateState)
                {
                    var predicateState = SASTStates.SingleOrDefault(x => x.Name.Equals(predicate.State, StringComparison.InvariantCultureIgnoreCase));
                    if (predicateState?.State.HasValue == true)
                        newBody.State = predicateState.State.Value.ToString();
                    else if (predicateState != null)
                        newBody.CustomStateId = predicateState.Id;
                }
                else
                {
                    var sastState = SASTStates.SingleOrDefault(x => x.Name.Equals(result.State, StringComparison.InvariantCultureIgnoreCase));
                    if (sastState.State.HasValue)
                        newBody.State = sastState.State.Value.ToString();
                    else
                        newBody.CustomStateId = sastState.Id;
                }

                body.Add(newBody);
            }

            if (body.Any())
            {
                SASTResultsPredicates.PredicateBySimiliartyIdAndProjectIdAsync(body).Wait();
                return true;
            }

            return false;
        }

        public void MarkSASTResult(Guid projectId, string similarityId, ResultsSeverity severity, string state, Guid scanId, string comment = null)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentException(nameof(projectId));

            PredicateBySimiliartyIdBody newBody = new PredicateBySimiliartyIdBody
            {
                SimilarityId = similarityId,
                ProjectId = projectId,
                ScanId = scanId,
                Severity = severity
            };

            var sastState = SASTStates.SingleOrDefault(x => x.Name.Equals(state, StringComparison.InvariantCultureIgnoreCase));
            if (sastState.State.HasValue)
                newBody.State = sastState.State.Value.ToString();
            else
                newBody.CustomStateId = sastState.Id;

            if (!string.IsNullOrWhiteSpace(comment))
                newBody.Comment = comment;

            SASTResultsPredicates.PredicateBySimiliartyIdAndProjectIdAsync(new PredicateBySimiliartyIdBody[] { newBody }).Wait();
        }

        /// <summary>
        /// Mark IaC, KICS results.
        /// </summary>
        /// <param name="projectId"></param>
        /// <returns></returns>
        /// <exception cref="NotSupportedException"></exception>
        public bool MarkKICSResult(Guid projectId, string similarityId, Services.KicsResults.SeverityEnum severity, string state, string comment = null)
        {
            if (string.IsNullOrWhiteSpace(similarityId))
                throw new ArgumentNullException(nameof(similarityId));

            if (projectId == Guid.Empty)
                throw new ArgumentException(nameof(projectId));

            var postPredicate = new POSTPredicate()
            {
                SimilarityId = similarityId,
                ProjectId = projectId,
                Severity = severity,
                Comment = comment
            };

            if (KICSResultsPredicates.TryGetKicsState(state, out var enumState))
            {
                postPredicate.State = enumState;
                postPredicate.CustomStateId = null;
            }
            else
            {
                var customState = KicsStates.FirstOrDefault(x => x.Name == state);
                if (customState == null)
                    throw new Exception($"IaC custom state \"{state}\" not found.");

                postPredicate.State = null;
                postPredicate.CustomStateId = customState.Id;
            }

            KicsResultsPredicates.UpdateAsync(new[] { postPredicate }).Wait();

            return true;
        }

        public void MarkSCAPackage(Guid projectId, string packageManager, string packageName, string packageVersion, PackageStateEnum packageState, string message, DateTimeOffset? endDate = null)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentNullException(nameof(projectId));

            if (string.IsNullOrEmpty(packageManager))
                throw new ArgumentNullException(nameof(packageManager));

            if (string.IsNullOrEmpty(packageName))
                throw new ArgumentNullException(nameof(packageName));

            if (string.IsNullOrEmpty(packageVersion))
                throw new ArgumentNullException(nameof(packageVersion));

            if (string.IsNullOrEmpty(message))
                throw new ArgumentNullException(nameof(message));

            if (packageState == PackageStateEnum.Snooze && endDate == null)
                endDate = DateTimeOffset.UtcNow;

            var body = new ScaUpdatePackageBody
            {
                PackageManager = packageManager,
                PackageName = packageName,
                PackageVersion = packageVersion,
                Actions = [new PackageActionType
                {
                    Type = PackageActionTypeEnum.Ignore,
                    Value = new Services.PackageState{ State = packageState, EndDate = endDate },
                    Comment = message
                }],
                ProjectId = projectId
            };

            SCA.UpdatePackageState(body).Wait();
        }

        private static readonly Dictionary<string, double> severityScoreMap =
            new(StringComparer.OrdinalIgnoreCase)
            {
                ["CRITICAL"] = 9,
                ["HIGH"] = 7,
                ["MEDIUM"] = 4,
                ["LOW"] = 0.1,
                ["INFO"] = 0
            };

        public void MarkSCAVulnerability(Guid projectId, Vulnerability vulnerabilityRisk,
            string vulnerabilityStatus = null, string message = null, string severityOrScore = null)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentNullException(nameof(projectId));

            if (vulnerabilityRisk == null)
                throw new ArgumentNullException(nameof(vulnerabilityRisk));

            if (string.IsNullOrEmpty(message))
                throw new ArgumentNullException(nameof(message));

            if (string.IsNullOrWhiteSpace(vulnerabilityStatus) && string.IsNullOrWhiteSpace(severityOrScore))
                throw new ArgumentNullException($"In order to mark an SCA vulnerability, at least one of the following should have a value: {nameof(vulnerabilityStatus)}, {nameof(severityOrScore)}");

            var body = new ScaPackageInfo
            {
                PackageManager = vulnerabilityRisk.PackageManager,
                PackageName = vulnerabilityRisk.PackageName,
                PackageVersion = vulnerabilityRisk.PackageVersion,
                VulnerabilityId = vulnerabilityRisk.Id,
                ProjectIds = [projectId]
            };

            List<ActionType> actions = new List<ActionType>();

            if (!string.IsNullOrWhiteSpace(vulnerabilityStatus))
            {
                var state = SCAStates.FirstOrDefault(x => x.Name == vulnerabilityStatus);
                if (state == null)
                    throw new Exception($"SCA state \"{vulnerabilityStatus}\" not found.");

                if (state.State == null)
                    vulnerabilityStatus = state.Id.ToString();

                actions.Add(new ActionType
                {
                    Type = ActionTypeEnum.ChangeState,
                    Value = vulnerabilityStatus,
                    Comment = message
                });
            }

            if (!string.IsNullOrWhiteSpace(severityOrScore))
            {
                double score;

                if (!double.TryParse(severityOrScore, NumberStyles.Float, CultureInfo.InvariantCulture, out score)
                    || score < 0 || score > 10)
                {
                    if (!severityScoreMap.TryGetValue(severityOrScore.Trim(), out score))
                        throw new ArgumentException($"Invalid severity value: {severityOrScore}");
                }

                actions.Add(new ActionType
                {
                    Type = ActionTypeEnum.ChangeScore,
                    Value = score.ToString(),
                    Comment = message
                });
            }

            body.Actions = actions.ToArray();

            SCA.UpdateResultState(body).Wait();
        }

        public StatsCompareResult GetScanResultsCompare(Guid baseScanId, Guid scanId)
        {
            if (scanId == Guid.Empty)
                throw new ArgumentException(nameof(scanId));

            if (baseScanId == Guid.Empty)
                throw new ArgumentException(nameof(baseScanId));

            return SASTScanResultsCompare.StatusAsync(baseScanId, scanId).Result;
        }

        #endregion

        #region SAST Results Predicates

        public void RecalculateSummaryCounters(Guid projectId, Guid scanId)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentException(nameof(projectId));

            if (scanId == Guid.Empty)
                throw new ArgumentException(nameof(scanId));

            SASTResultsPredicates.RecalculateSummaryCountersAsync(new RecalculateBody { ProjectId = projectId, ScanId = scanId })
                .GetAwaiter()
                .GetResult();
        }

        #endregion

        #region Configurations

        public void SetProjectConfig(Guid projectId, string key, object value)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentException(nameof(projectId));

            if (string.IsNullOrWhiteSpace(key))
                throw new ArgumentException(nameof(key));

            if (value == null)
            {
                Configuration.ProjectDELETEParameterAsync(projectId, key).Wait();
                return;
            }

            List<ScanParameter> body =
            [
                new ScanParameter()
                {
                    Key = key,
                    Value = value.ToString()
                }
            ];

            Configuration.UpdateProjectConfigurationAsync(projectId.ToString(), body).Wait();
        }

        public string GetProjectConfig(Guid projectId, string configKey)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentException(nameof(projectId));

            var configuration = GetProjectConfigurations(projectId);
            if (configuration.ContainsKey(configKey))
            {
                var config = configuration[configKey];

                if (config != null && !string.IsNullOrWhiteSpace(config.Value))
                    return config.Value;
            }

            return null;
        }

        public string GetScanConfig(Guid projectId, Guid scanId, string configKey)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentException(nameof(projectId));

            if (scanId == Guid.Empty)
                throw new ArgumentException(nameof(scanId));

            var configuration = GetScanConfigurations(projectId, scanId);
            if (configuration.ContainsKey(configKey))
            {
                var config = configuration[configKey];

                if (config != null && !string.IsNullOrWhiteSpace(config.Value))
                    return config.Value;
            }

            return null;
        }

        public string GetConfigValue(Guid projectId, string configKey)
        {
            string projectConfigValue = GetProjectConfig(projectId, configKey);
            if (string.IsNullOrEmpty(projectConfigValue))
            {
                var tenant_config = GetTenantConfigurations();
                return tenant_config.ContainsKey(configKey) ? tenant_config[configKey].Value : null;
            }

            return projectConfigValue;
        }

        public Dictionary<string, ScanParameter> GetTenantConfigurations()
        {
            return Configuration.TenantAllAsync().Result?.ToDictionary(x => x.Key, y => y);
        }

        public Dictionary<string, ScanParameter> GetProjectConfigurations(Guid projectId)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentException(nameof(projectId));

            return Configuration.ProjectAllAsync(projectId).Result?.ToDictionary(x => x.Key, y => y);
        }

        public Dictionary<string, ScanParameter> GetScanConfigurations(Guid projectId, Guid scanId)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentException(nameof(projectId));

            if (scanId == Guid.Empty)
                throw new ArgumentException(nameof(scanId));

            return Configuration.ScanAsync(projectId, scanId).Result?.ToDictionary(x => x.Key, y => y);
        }

        public void DeleteTenantConfiguration(string config_keys)
        {
            if (string.IsNullOrWhiteSpace(config_keys))
                throw new ArgumentException(nameof(config_keys));

            Configuration.TenantDELETEParameterAsync(config_keys).Wait();
        }

        public void DeleteProjectConfiguration(Guid projectId, string config_keys)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentException(nameof(projectId));

            if (string.IsNullOrWhiteSpace(config_keys))
                throw new ArgumentException(nameof(config_keys));

            Configuration.ProjectDELETEParameterAsync(projectId, config_keys).Wait();
        }

        public string GetScanPresetFromConfigurations(Guid projectId, Guid scanId) => GetScanConfig(projectId, scanId, SettingsProjectPreset);

        public string GetScanExclusionsFromConfigurations(Guid projectId, Guid scanId) => GetScanConfig(projectId, scanId, SettingsProjectExclusions);

        public IEnumerable<ScanParameter> GetTenantProjectConfigurations()
        {
            return GetTenantConfigurations().Where(x => x.Value.Key == SettingsProjectConfiguration).Select(x => x.Value);
        }

        public enum ResultScopeLevel
        {
            Project,
            Application
        }

        public ResultScopeLevel GetResultsScopeLevel()
        {
            var value = GetTenantConfigurations().Single(x => x.Value.Key == SettingsResultsScopeLevel).Value.Value;

            switch (value)
            {
                // In case is not set the default Result Scope is Project
                case "":
                case null:
                case "Project": return ResultScopeLevel.Project;
                case "Application": return ResultScopeLevel.Application;
                default: throw new NotSupportedException($"Value {value} not supported for Result Scope Level");
            }
        }

        public void SetResultsScopeLevel(ResultScopeLevel level)
        {
            List<ScanParameter> body = new List<ScanParameter>()
            {
                new ScanParameter()
                {
                    Key = SettingsResultsScopeLevel,
                    Value = level.ToString(),
                    AllowOverride = false
                }
            };

            Configuration.UpdateTenantConfigurationAsync(body).Wait();
        }

        public string GetProjectRepoUrl(Guid projectId) => GetProjectConfig(projectId, SettingsProjectRepoUrl);

        public string GetProjectConfiguration(Guid projectId) => GetProjectConfig(projectId, SettingsProjectConfiguration);

        public string GetProjectExclusions(Guid projectId) => GetProjectConfig(projectId, SettingsProjectExclusions);

        public string GetProjectAPISecuritySwaggerFolderFileFilter(Guid projectId) => GetProjectConfig(projectId, SettingsAPISecuritySwaggerFolderFileFilter);

        public void SetProjectExclusions(Guid projectId, string exclusions) => SetProjectConfig(projectId, SettingsProjectExclusions, exclusions);

        public Tuple<string, string> GetProjectFilesAndFoldersExclusions(Guid projectId)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentException(nameof(projectId));

            var config = GetProjectExclusions(projectId);
            if (!string.IsNullOrWhiteSpace(config))
            {
                char[] delimiters = new[] { ',', ';' };
                var exclusions = config.Split(delimiters, StringSplitOptions.RemoveEmptyEntries).ToList().Select(x => x.Trim());

                var filesList = exclusions.Where(x => x.StartsWith("."));
                var foldersList = exclusions.Where(x => !x.StartsWith("."));

                var files = filesList.Any() ? string.Join(",", filesList) : string.Empty;
                var folders = foldersList.Any() ? string.Join(",", foldersList) : string.Empty;

                return new Tuple<string, string>(files, folders);
            }

            return new Tuple<string, string>(string.Empty, string.Empty);
        }

        public string GetTenantAPISecuritySwaggerFolderFileFilter()
        {
            var configuration = GetTenantConfigurations();
            if (configuration.ContainsKey(SettingsAPISecuritySwaggerFolderFileFilter))
            {
                var config = configuration[SettingsAPISecuritySwaggerFolderFileFilter];

                if (config != null && !string.IsNullOrWhiteSpace(config.Value))
                    return config.Value;
            }

            return null;
        }

        public void SetTenantAPISecuritySwaggerFolderFileFilter(string filter = null, bool allowOverride = false)
        {
            if (filter == null)
            {
                // Delete current value
                DeleteTenantConfiguration(SettingsAPISecuritySwaggerFolderFileFilter);
                return;
            }

            List<ScanParameter> body = new List<ScanParameter>() {
                new ScanParameter()
                {
                    Key = SettingsAPISecuritySwaggerFolderFileFilter,
                    Value = filter,
                    AllowOverride = allowOverride
                }
            };

            Configuration.UpdateTenantConfigurationAsync(body).Wait();
        }

        public void SetProjectAPISecuritySwaggerFolderFileFilter(Guid projectId, string filter = null, bool allowOverride = false)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentException(nameof(projectId));

            if (filter == null)
            {
                // Delete current parameter
                DeleteProjectConfiguration(projectId, SettingsAPISecuritySwaggerFolderFileFilter);
                return;
            }

            List<ScanParameter> body = new List<ScanParameter>() {
                new ScanParameter()
                {
                    Key = SettingsAPISecuritySwaggerFolderFileFilter,
                    Value = filter,
                    AllowOverride = allowOverride
                }
            };

            Configuration.UpdateProjectConfigurationAsync(projectId.ToString(), body).Wait();
        }

        public async Task<Dictionary<Guid, string>> GetScanEngineVersionAsync(IEnumerable<Guid> scans)
        {
            if (scans == null || !scans.Any())
                throw new ArgumentNullException(nameof(scans));

            Dictionary<Guid, string> engineVersions = scans.ToDictionary(x => x, x => (string)null);

            int batchSize = 10;
            List<Task<IEnumerable<ScanEngineVersionInfo>>> tasks = new List<Task<IEnumerable<ScanEngineVersionInfo>>>();

            foreach (var batch in scans.Chunk(batchSize))
            {
                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        return await SASTMetadata.EngineVersionAsync(batch);
                    }
                    catch (Exceptions.ApiException apiEx)
                    {
                        if (apiEx.StatusCode == 404)
                            return Enumerable.Empty<ScanEngineVersionInfo>();
                        else
                            throw;
                    }
                }));
            }

            var results = await Task.WhenAll(tasks);

            foreach (var engineVersionsResult in results)
            {
                foreach (var result in engineVersionsResult)
                    engineVersions[result.ScanId] = result.EngineVersion;
            }

            return engineVersions;
        }


        #endregion

        #region Presets

        public IEnumerable<PresetDetails> GetCustomPresetsDetails()
        {
            return GetAllPresets().Where(x => x.Custom == true)
                .AsParallel()
                .Select(preset => PresetManagement.GetPresetById(Scanner.Sast, preset.Id).Result)
                .ToList();
        }

        public IEnumerable<PresetDetails> GetAllPresetsDetails()
        {
            return GetAllPresets()
                .AsParallel()
                .Select(preset => PresetManagement.GetPresetById(Scanner.Sast, preset.Id).Result)
                .ToList();
        }

        public IEnumerable<PresetSummary> GetAllPresets(int limit = 20)
        {
            if (limit <= 0)
                throw new ArgumentOutOfRangeException(nameof(limit));

            var result = new List<PresetSummary>();
            var offset = 0;

            while (true)
            {
                var page = PresetManagement.GetPresetsAsync(Scanner.Sast, limit, offset, include_details: true).Result;

                if (page.Presets != null)
                    result.AddRange(page.Presets);

                offset += limit;

                if (page.TotalCount == 0 || page.TotalCount == result.Count)
                {
                    // Found a tenant with duplicated presets (same ID, Name, settings, etc)
                    // As a workaround, we are grouping by preset ID and taking the first one, since all duplicates have the same details
                    var dupePresets = result
                        .GroupBy(p => p.Id)
                        .Where(g => g.Count() > 1)
                        .Select(g => $"[{g.Key}] {string.Join(" / ", g.GroupBy(p => p.Name).Select(n => n.Count() > 1 ? $"{n.Key} ({n.Count()})" : n.Key))}")
                        .ToList();

                    if (dupePresets.Any())
                        Console.WriteLine($"[GetAllPresets] Duplicate presets found with the same Id: {string.Join(", ", dupePresets)}. Please check the tenant's preset configuration.");

                    return result
                        .GroupBy(p => p.Id)
                        .Select(g => g.First());
                }
            }
        }

        #endregion

        #region Queries

        /// <summary>
        /// Result of a single query read/create/override attempt made as part of a batch.
        /// </summary>
        public class QueryBatchResult
        {
            public string Language { get; set; }
            public string QueryName { get; set; }
            public bool Success { get; set; }
            public string ErrorMessage { get; set; }
            public string Source { get; set; }
        }

        public class TenantQueryUpsert
        {
            public string Language { get; set; }
            public string QueryName { get; set; }
            public string QuerySource { get; set; }

            /// <summary>Required only when the query does not exist yet at Cx or Tenant level.</summary>
            public string Group { get; set; }
            public string Severity { get; set; }
            public bool? IsExecutable { get; set; }
        }

        public class ProjectQueryUpsert
        {
            public string Language { get; set; }
            public string QueryName { get; set; }
            public string QuerySource { get; set; }
        }

        /// <summary>
        /// Retrieves every query defined anywhere in the tenant — Cx, Tenant, Project and
        /// Application level, all correctly resolved.
        ///
        /// Cx, Tenant and Project level come from the plain listing endpoint per project — cheap,
        /// sessionless, and reliable for those three levels; fetched in parallel across projects,
        /// since there is no session budget to protect for this part. Application level does NOT come
        /// from that endpoint: it was confirmed to silently lag behind (or outright miss) a
        /// just-created or just-edited override, so it is read through a real query editor session
        /// instead (<see cref="GetApplicationLevelQueriesFromSession"/>, via QueryEditorClient) — but
        /// only once per Application, not once per member project. For each Application, one
        /// representative candidate is picked up front, before any session is opened: a member project
        /// that belongs to only that one Application (any project belonging to more than one is a
        /// confirmed, deterministic server-side failure — "error getting queries" — for this exact
        /// call, every time) and has a scan (a session cannot be opened without one). Both signals are
        /// already known from data already loaded (<see cref="Apps"/>, <see cref="GetLastScan"/>)
        /// without opening any session, so a doomed candidate is never attempted in the first place —
        /// unlike the member-project loop this replaced, which tried every member project regardless
        /// and only found out a candidate was bad by letting it fail.
        ///
        /// This deliberately still stops short of CxOneInstance.GetApplicationLevelQueries's full
        /// resilience: if an Application's chosen representative fails anyway (a genuinely unexpected
        /// error, not the two known cases already filtered out), there is no second candidate tried —
        /// that Application's data is simply missed, surfaced via Trace.TraceWarning rather than a
        /// bare catch. Retrying via a fallback candidate on an unexpected failure is exactly the kind
        /// of business-logic resilience (deciding which project best represents which Application,
        /// and what to try next when the first choice doesn't work) that belongs in
        /// CxOneInstance.GetApplicationLevelQueries, not here.
        ///
        /// The Application-level phase runs with its degree of parallelism explicitly capped to
        /// QueryEditorClient's own concurrent-session budget rather than left to Parallel.ForEach's
        /// default (typically the machine's core count): the semaphore inside session creation already
        /// prevents exceeding that budget regardless, but letting far more threads than that pile up
        /// blocked on it needlessly consumes thread-pool threads and risks later ones timing out
        /// waiting for a turn on a large tenant, for no benefit — nothing beyond the budget can make
        /// progress anyway.
        /// </summary>
        /// <returns>
        /// A dictionary mapping query IDs to queries, resolved to the most specific level defined for
        /// each ID (Project &gt; Application &gt; Tenant &gt; Cx).
        /// </returns>
        public Dictionary<string, Services.SASTQueriesAudit.Queries> GetAllQueries()
        {
            var allQueries = new ConcurrentBag<Services.SASTQueriesAudit.Queries>(getQueries());

            Parallel.ForEach(GetAllProjectsDetails(), project =>
            {
                foreach (var query in getQueries(project.Id, x => x.Level != Query_Level_Application))
                    allQueries.Add(query);
            });

            // Picking a representative candidate per Application involves a real network call
            // (GetLastScan) per candidate tried — sessionless, but not free, so this is parallelized
            // across Applications too, same as the two phases around it. No degree-of-parallelism cap
            // needed here: nothing in this phase touches the query editor session budget.
            var representativeProjectIds = new ConcurrentBag<Guid>();
            Parallel.ForEach(Apps.Applications ?? Enumerable.Empty<Services.Applications.Application>(), application =>
            {
                var candidate = (application.ProjectIds ?? Enumerable.Empty<Guid>())
                    .FirstOrDefault(projectId => GetProjectApplications(projectId).Count() == 1 && GetLastScan(projectId, completed: false) != null);

                if (candidate != Guid.Empty)
                    representativeProjectIds.Add(candidate);
            });

            var sessionOptions = new ParallelOptions { MaxDegreeOfParallelism = QueryEditorClient.MaxConcurrentSessions };
            Parallel.ForEach(representativeProjectIds.Distinct(), sessionOptions, representativeProjectId =>
            {
                try
                {
                    foreach (var query in queryEditorClient.GetApplicationLevelQueriesFromSession(representativeProjectId).Select(toQueriesModel))
                        allQueries.Add(query);
                }
                catch (Exception ex)
                {
                    // Genuinely unexpected: the two known, deterministic failure reasons (shared
                    // membership, no scan) were already excluded when this candidate was picked.
                    // Surfaced via Trace (same mechanism used elsewhere in this class for warnings
                    // with no logger available) instead of a bare catch, so it is visible to test
                    // runners and any caller with a Trace listener attached rather than silently
                    // discarded.
                    System.Diagnostics.Trace.TraceWarning($"[GetAllQueries] Could not read Application-level queries via project {representativeProjectId}: {ex.Message}");
                }
            });

            return getQueriesDictionary(allQueries);
        }

        /// <summary>
        /// Retrieves a dictionary of queries scoped by priority: Project → Application → Tenant → Cx.
        /// Project and Application level are only included when the projectId parameter is given —
        /// the plain listing endpoint returns whichever of those overrides apply to that project
        /// mixed in with the tenant-wide Cx/Tenant queries.
        ///
        /// Deliberately kept cheap and sessionless, including for Application-level data: this method
        /// has real, existing callers (e.g. CxOneInstance.GetProjectLevelQueries, exercised in
        /// parallel across every project of a tenant by the query report and query migration) that
        /// depend on it being fast and safe to call freely without touching the query editor session
        /// budget. That means its Application-level data can lag briefly behind a just-created or
        /// just-edited override — use <see cref="GetApplicationLevelQueries"/> (session-based, one
        /// query editor session, only for this exact project) or <see cref="GetAllQueries"/>
        /// (tenant-wide) when that guarantee matters more than staying cheap.
        /// </summary>
        /// <param name="projectId">The ID of the project to retrieve queries for. Project- and Application-level queries override Tenant/Cx level queries with the same ID</param>
        /// <returns>
        /// A dictionary mapping query IDs to queries, resolved to the most specific level defined for
        /// each ID (Project &gt; Application &gt; Tenant &gt; Cx).
        /// </returns>
        public Dictionary<string, Services.SASTQueriesAudit.Queries> GetQueries(Guid? projectId = null)
        {
            return getQueriesDictionary(getQueries(projectId));
        }

        /// <summary>
        /// Retrieves a dictionary of Cx Level queries.
        /// </summary>
        /// <returns>
        /// A dictionary mapping query IDs to queries at a Cx level.
        /// </returns>
        public Dictionary<string, Services.SASTQueriesAudit.Queries> GetCxLevelQueries()
        {
            return getQueriesDictionary(getQueries(predicate: x => x.Level == ASTClient.Query_Level_Cx));
        }

        /// <summary>
        /// Retrieves a dictionary of Tenant Level queries.
        /// </summary>
        /// <returns>
        /// A dictionary mapping query IDs to queries at a Tenant level.
        /// </returns>
        public Dictionary<string, Services.SASTQueriesAudit.Queries> GetTenantLevelQueries()
        {
            return getQueriesDictionary(getQueries(predicate: x => x.Level == ASTClient.Query_Level_Tenant));
        }

        /// <summary>
        /// Retrieves a dictionary of Application Level queries visible through the given project —
        /// i.e. the queries overridden by the Application(s) this project belongs to, if any. Reads
        /// through a real query editor session (<see cref="GetApplicationLevelQueriesFromSession"/>)
        /// rather than the plain listing endpoint, which was confirmed to silently lag behind a
        /// just-created or just-edited override.
        ///
        /// Fast path: a project belonging to zero or one Application is read through directly — one
        /// query editor session, no extra checks. This is the common case.
        ///
        /// A project belonging to more than one Application cannot be read through directly: that is
        /// a confirmed, deterministic CxOne API limitation (reliably fails with an opaque "error
        /// getting queries" every time, not just sometimes). Rather than failing outright, each
        /// Application the given project belongs to is checked for a *different* project that belongs
        /// to only that one Application and has a scan, and read through that instead — so passing in
        /// a shared project still succeeds whenever its Applications have another, unshared project to
        /// fall back on. Only when at least one of those Applications has no such alternative does this
        /// throw, and the exception names exactly which Application(s) could not be resolved. This
        /// check is done up front, before any session is opened, so a failure never wastes a session
        /// attempt on a read already known to be doomed.
        ///
        /// For tenant-wide discovery across every Application in the tenant (not just the one(s)
        /// reachable from a single known project), with the retry-on-failure resilience this method
        /// still doesn't have (an Application whose *only* candidates are all shared or scanless is
        /// still unresolved here), use CxOneInstance.GetApplicationLevelQueries instead — that belongs
        /// at the business-logic layer, not here.
        /// </summary>
        /// <param name="projectId">The ID of a project belonging to the Application to retrieve queries for.</param>
        /// <returns>
        /// A dictionary mapping query IDs to queries at an Application level.
        /// </returns>
        public Dictionary<string, Services.SASTQueriesAudit.Queries> GetApplicationLevelQueries(Guid projectId)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentException(nameof(projectId));

            var applications = (GetProjectApplications(projectId) ?? Enumerable.Empty<Services.Applications.Application>()).ToList();

            if (applications.Count <= 1)
                return getQueriesDictionary(queryEditorClient.GetApplicationLevelQueriesFromSession(projectId).Select(toQueriesModel));

            var candidates = applications
                .Select(application => (
                    Application: application,
                    Alternative: (application.ProjectIds ?? Enumerable.Empty<Guid>())
                        .FirstOrDefault(pid => GetProjectApplications(pid).Count() == 1 && GetLastScan(pid, completed: false) != null)))
                .ToList();

            var unresolved = candidates.Where(x => x.Alternative == Guid.Empty).Select(x => x.Application.Name).ToList();
            if (unresolved.Any())
                throw new NotSupportedException($"Project {projectId} belongs to more than one Application ({string.Join(", ", applications.Select(a => a.Name))}), and the following have no other project that could be used to read their Application-level queries instead: {string.Join(", ", unresolved)}. Reading through a project shared by multiple Applications is a confirmed CxOne API limitation.");

            return getQueriesDictionary(candidates.SelectMany(x => queryEditorClient.GetApplicationLevelQueriesFromSession(x.Alternative).Select(toQueriesModel)));
        }

        /// <summary>
        /// Retrieves a dictionary of Project Level queries.
        /// </summary>
        /// <param name="projectId">The ID of the project to retrieve queries for.</param>
        /// <returns>
        /// A dictionary mapping query IDs to queries at a Project level.
        /// </returns>
        public Dictionary<string, Services.SASTQueriesAudit.Queries> GetProjectLevelQueries(Guid projectId)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentException(nameof(projectId));

            return getQueriesDictionary(getQueries(projectId, x => x.Level == ASTClient.Query_Level_Project));
        }

        // Everything below that reads/writes an actual query (rather than just listing them) goes
        // through a real query editor session, and lives in QueryEditorClient
        // (Services/QueryEditorClient.cs) — that class owns the session lifecycle, the tenant-wide
        // slot budget, and its own retry policy tuned for the specific ways session creation is known
        // to fail. These stay here as thin delegates purely so no existing caller anywhere else in the
        // solution had to change.

        /// <summary>
        /// Get the Query Source by language and name. See <see cref="QueryEditorClient.GetQuerySource"/>.
        /// </summary>
        public string GetQuerySource(string language, string queryName, Guid? projectId = null, Guid? scanId = null) =>
            queryEditorClient.GetQuerySource(language, queryName, projectId, scanId);

        /// <summary>
        /// Overrides a query at a project level. See <see cref="QueryEditorClient.OverrideProjectQuerySource"/>.
        /// </summary>
        public void OverrideProjectQuerySource(Guid projectId, string language, string queryName, string querySource, Guid? scanId = null) =>
            queryEditorClient.OverrideProjectQuerySource(projectId, language, queryName, querySource, scanId);

        /// <summary>
        /// Overrides a query at an Application level. See <see cref="QueryEditorClient.OverrideApplicationQuerySource"/>.
        /// </summary>
        public void OverrideApplicationQuerySource(Guid projectId, string language, string queryName, string querySource, Guid? scanId = null) =>
            queryEditorClient.OverrideApplicationQuerySource(projectId, language, queryName, querySource, scanId);

        /// <summary>
        /// Creates or overrides several Application-level queries through a single project's session.
        /// See <see cref="QueryEditorClient.CreateOrOverrideApplicationQuerySources"/>.
        /// </summary>
        public IEnumerable<QueryBatchResult> CreateOrOverrideApplicationQuerySources(Guid representativeProjectId, IEnumerable<ProjectQueryUpsert> queries, Guid? scanId = null) =>
            queryEditorClient.CreateOrOverrideApplicationQuerySources(representativeProjectId, queries, scanId);

        /// <summary>
        /// Overrides a query at a tenant level. See <see cref="QueryEditorClient.OverrideTenantQuerySource"/>.
        /// </summary>
        public void OverrideTenantQuerySource(string language, string queryName, string querySource) =>
            queryEditorClient.OverrideTenantQuerySource(language, queryName, querySource);

        /// <summary>
        /// Create a query at a tenant level. See <see cref="QueryEditorClient.CreateTenantQuery"/>.
        /// </summary>
        public void CreateTenantQuery(string language, string queryName, string group, string severity, string source, bool isExecutable) =>
            queryEditorClient.CreateTenantQuery(language, queryName, group, severity, source, isExecutable);

        #region Batched Query Editor Operations

        /// <summary>
        /// Reads the source of several Tenant-level queries, opening one session per distinct
        /// language instead of one session per query. See <see cref="QueryEditorClient.GetTenantQuerySources"/>.
        /// </summary>
        public IEnumerable<QueryBatchResult> GetTenantQuerySources(IEnumerable<(string Language, string QueryName)> queries) =>
            queryEditorClient.GetTenantQuerySources(queries);

        /// <summary>
        /// Reads the source of several Project-level queries for a single project/scan, opening
        /// exactly one session for the whole call instead of one session per query. See
        /// <see cref="QueryEditorClient.GetProjectQuerySources"/>.
        /// </summary>
        public IEnumerable<QueryBatchResult> GetProjectQuerySources(Guid projectId, IEnumerable<(string Language, string QueryName)> queries, Guid? scanId = null) =>
            queryEditorClient.GetProjectQuerySources(projectId, queries, scanId);

        /// <summary>
        /// Creates or overrides several Tenant-level queries, opening one session per distinct
        /// language instead of one (or two, via a separate existence probe) session per query. See
        /// <see cref="QueryEditorClient.CreateOrOverrideTenantQuerySources"/>.
        /// </summary>
        public IEnumerable<QueryBatchResult> CreateOrOverrideTenantQuerySources(IEnumerable<TenantQueryUpsert> queries) =>
            queryEditorClient.CreateOrOverrideTenantQuerySources(queries);

        /// <summary>
        /// Creates or overrides several Project-level queries for a single project/scan, opening
        /// exactly one session for the whole call instead of one session per query. See
        /// <see cref="QueryEditorClient.CreateOrOverrideProjectQuerySources"/>.
        /// </summary>
        public IEnumerable<QueryBatchResult> CreateOrOverrideProjectQuerySources(Guid projectId, IEnumerable<ProjectQueryUpsert> queries, Guid? scanId = null) =>
            queryEditorClient.CreateOrOverrideProjectQuerySources(projectId, queries, scanId);

        #endregion

        /// <summary>
        /// Deletes a query at a Project level. See <see cref="QueryEditorClient.DeleteProjectQuery"/>.
        /// </summary>
        public bool DeleteProjectQuery(Guid projectId, string language, string queryName, string withQueryDescription = null, Guid? scanId = null) =>
            queryEditorClient.DeleteProjectQuery(projectId, language, queryName, withQueryDescription, scanId);

        /// <summary>
        /// Deletes a query at an Application level. See <see cref="QueryEditorClient.DeleteApplicationQuery"/>.
        /// </summary>
        public bool DeleteApplicationQuery(Guid projectId, string language, string queryName, string withQueryDescription = null, Guid? scanId = null) =>
            queryEditorClient.DeleteApplicationQuery(projectId, language, queryName, withQueryDescription, scanId);

        /// <summary>
        /// Deletes a query at a Tenant level. See <see cref="QueryEditorClient.DeleteTenantQuery"/>.
        /// </summary>
        public bool DeleteTenantQuery(string language, string queryName, string withQueryDescription = null) =>
            queryEditorClient.DeleteTenantQuery(language, queryName, withQueryDescription);

        /// <summary>
        /// Deletes a query at a Project or Tenant level through the query editor key. See
        /// <see cref="QueryEditorClient.DeleteQueryByKey"/>.
        /// </summary>
        public bool DeleteQueryByKey(string queryKey, string language, Guid? projectId = null, Guid? scanId = null) =>
            queryEditorClient.DeleteQueryByKey(queryKey, language, projectId, scanId);

        /// <summary>
        /// Query details by language and name. See <see cref="QueryEditorClient.GetQueryByLanguageAndName"/>.
        /// </summary>
        public QueryResponse GetQueryByLanguageAndName(string language, string queryName, string level, Guid? projectId = null, Guid? scanId = null) =>
            queryEditorClient.GetQueryByLanguageAndName(language, queryName, level, projectId, scanId);

        /// <summary>
        /// Scan Query Nodes. See <see cref="QueryEditorClient.GetProjectScanQueryNodes"/>.
        /// </summary>
        public IEnumerable<Checkmarx.API.AST.Services.QueryEditor.QueriesTree> GetProjectScanQueryNodes(Guid projectId, Guid scanId) =>
            queryEditorClient.GetProjectScanQueryNodes(projectId, scanId);

        /// <summary>
        /// Discovers Application-level query overrides visible through a given project's query
        /// editor session. See <see cref="QueryEditorClient.GetApplicationLevelQueriesFromSession"/>.
        /// </summary>
        public IEnumerable<Services.QueryEditor.QueryResponse> GetApplicationLevelQueriesFromSession(Guid projectId, Guid? scanId = null) =>
            queryEditorClient.GetApplicationLevelQueriesFromSession(projectId, scanId);

        #region Private Methods

        private IEnumerable<Services.SASTQueriesAudit.Queries> getQueries(Guid? projectId = null, Predicate<Services.SASTQueriesAudit.Queries> predicate = null)
        {
            IEnumerable<Services.SASTQueriesAudit.Queries> queries = SASTQueriesAudit.QueriesAllAsync(projectId).Result;

            if (predicate != null)
                queries = queries.Where(q => predicate(q));

            return queries;
        }

        // Converts a real query editor session's detail (Services.QueryEditor.QueryResponse, as
        // returned by GetApplicationLevelQueriesFromSession) into the lighter Services.SASTQueriesAudit.Queries
        // shape used everywhere else — the same field mapping CxOneInstance uses for the same purpose.
        private static Services.SASTQueriesAudit.Queries toQueriesModel(Services.QueryEditor.QueryResponse detail) =>
            new Services.SASTQueriesAudit.Queries
            {
                Id = detail.Id,
                Name = detail.Name,
                Level = detail.Level,
                Lang = detail.Metadata?.Language,
                Group = detail.Metadata?.Group,
                Path = detail.Path,
                Severity = detail.Metadata?.Severity,
                IsExecutable = detail.Metadata?.Executable ?? false
            };

        // Project > Application > Tenant > Cx. The listing endpoint can return the same query Id
        // twice — once as its base definition, once as a more specific override — and which one
        // comes first in the response is not guaranteed. An explicit rank (rather than the previous
        // pairwise "Project always wins, Tenant wins unless existing is Project" checks) is what
        // makes this correct regardless of response order: the old logic had no Application branch
        // at all, so an Application-level override sharing an Id with its Tenant/Cx base could be
        // silently dropped (if the base came second) or, worse, replaced back with the base (if the
        // Tenant entry came after the Application one — Tenant only checked "existing != Project").
        private static readonly Dictionary<string, int> queryLevelRank = new Dictionary<string, int>
        {
            [Query_Level_Cx] = 0,
            [Query_Level_Tenant] = 1,
            [Query_Level_Application] = 2,
            [Query_Level_Project] = 3
        };

        private Dictionary<string, Services.SASTQueriesAudit.Queries> getQueriesDictionary(IEnumerable<Services.SASTQueriesAudit.Queries> queries)
        {
            Dictionary<string, Services.SASTQueriesAudit.Queries> dictionary = new Dictionary<string, Services.SASTQueriesAudit.Queries>();

            foreach (var query in queries)
            {
                if (!dictionary.TryGetValue(query.Id, out var existing) ||
                    queryLevelRank.GetValueOrDefault(query.Level) > queryLevelRank.GetValueOrDefault(existing.Level))
                {
                    dictionary[query.Id] = query;
                }
            }

            return dictionary;
        }

        #endregion

        #endregion

        #region Webhooks

        public ICollection<Webhook> GetWebhooks(int startAt = 0, int limit = 10)
        {
            if (limit <= 0)
                throw new ArgumentOutOfRangeException(nameof(limit));

            var result = new List<Webhook>();

            while (true)
            {
                var resultPage = Webhooks.GetTenantWebhooks(limit, startAt).Result;

                if (resultPage.Webhooks != null)
                    result.AddRange(resultPage.Webhooks);

                startAt += limit;

                if (resultPage.TotalCount == 0 || resultPage.TotalCount == result.Count)
                    return result;
            }
        }

        public enum WebhookEventType
        {
            scan_completed_successfully,
            project_created,
            scan_failed,
            scan_partial
        }

        public Webhook CreateWebhook(string name, string url, string secret, List<WebhookEventType> enabledEvents)
        {
            var body = getWebhookInputBody(name, url, secret, enabledEvents);

            return Webhooks.CreateTenantWebhook(body).Result;
        }

        public void UpdateWebhook(Guid id, string name, string url, string secret, List<WebhookEventType> enabledEvents)
        {
            if (id == Guid.Empty)
                throw new ArgumentNullException(nameof(id));

            var body = getWebhookInputBody(name, url, secret, enabledEvents);

            Webhooks.UpdateWebhook(id, body).Wait();
        }

        public void DeleteWebhook(Guid id)
        {
            if (id == Guid.Empty)
                throw new ArgumentNullException(nameof(id));

            Webhooks.DeleteWebhook(id).Wait();
        }

        private WebhookInput getWebhookInputBody(string name, string url, string secret, List<WebhookEventType> enabledEvents)
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentNullException(nameof(name));

            if (string.IsNullOrWhiteSpace(url))
                throw new ArgumentNullException(nameof(url));

            if (string.IsNullOrWhiteSpace(secret))
                throw new ArgumentNullException(nameof(secret));

            if (enabledEvents == null || !enabledEvents.Any())
                throw new ArgumentNullException(nameof(enabledEvents));

            return new WebhookInput()
            {
                Name = name,
                Config = new WebhookConfig()
                {
                    Url = url,
                    Secret = secret
                },
                EnabledEvents = enabledEvents.Select(x => x.ToString()).ToList(),
                Active = true
            };
        }

        #endregion

        #region GraphQL

        public SCALegalRisks GetSCAScanLegalRisk(Guid scanId)
        {
            if (scanId == Guid.Empty)
                throw new ArgumentNullException(nameof(scanId));

            var query = @"
                        query ($scanId: UUID!, $where: LegalRiskModelFilterInput) {
                            legalRisksByScanId(scanId: $scanId, where: $where) {
                                totalCount
                                risksLevelCounts {
                                    critical
                                    high
                                    medium
                                    low
                                    none
                                    empty
                                }
                            }
                        }";

            // Define variables for the query
            var variables = new
            {
                scanId = scanId
            };

            return GraphQLClient.GetSCAScanLegalRisks(query, variables);
        }

        public static ICollection<Vulnerability> GetNewSCAVulnerabilities(List<Vulnerability> firstList, List<Vulnerability> secondList)
        {
            if (firstList == null) throw new ArgumentNullException(nameof(firstList));
            if (secondList == null) throw new ArgumentNullException(nameof(secondList));

            var firstIds = new HashSet<string>(firstList.Select(v => v.Id));

            // Return vulnerabilities that are in secondList but not in firstList
            return secondList
                .Where(v => !string.IsNullOrEmpty(v.Id) && !firstIds.Contains(v.Id))
                .ToList();
        }

        #endregion

        #region Logs

        const string MULTI_LANGUAGE_MODE = "MULTI_LANGUAGE_MODE";

        public int GetSASTEngineLanguageMode(Guid scanId)
        {
            string log = GetScanLog(scanId, SAST_Engine);
            foreach (var item in log.Split("\n"))
            {
                if (item.Contains($"{MULTI_LANGUAGE_MODE}="))
                    return int.Parse(item.Replace($"{MULTI_LANGUAGE_MODE}=", ""));
            }

            throw new NotSupportedException($"{MULTI_LANGUAGE_MODE} not found");
        }

        public string GetSASTScanLog(Guid scanId)
        {
            return GetScanLogs(scanId, SAST_Engine).Result;
        }

        public string GetScanLog(Guid scanId, string engine)
        {
            return GetScanLogs(scanId, engine).Result;
        }

        private async Task<string> GetScanLogs(Guid scanId, string engine)
        {
            if (string.IsNullOrEmpty(engine))
                throw new ArgumentNullException(nameof(engine));

            string token = authenticate();
            string serverRestEndpoint = $"{ASTServer.AbsoluteUri}api/logs/{scanId}/{engine}";

            using (var handler = new RequestDescriptionHandler(new HttpClientHandler { AllowAutoRedirect = false }))
            using (var client = new HttpClient(handler))
            {
                client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

                using (var requestMessage = new HttpRequestMessage(HttpMethod.Get, serverRestEndpoint))
                {
                    var response = await _retryPolicy.ExecuteAsync(() => client.SendAsync(CloneHttpRequestMessage(requestMessage), HttpCompletionOption.ResponseHeadersRead)).ConfigureAwait(false);

                    try
                    {
                        if (response.StatusCode == HttpStatusCode.TemporaryRedirect || response.StatusCode == HttpStatusCode.Redirect)
                        {
                            string redirectUrl = response.Headers.Location?.ToString();
                            if (!string.IsNullOrEmpty(redirectUrl))
                            {
                                var redirectRequest = new HttpRequestMessage(HttpMethod.Get, redirectUrl);

                                var redirectResponse = await _retryPolicy.ExecuteAsync(() => client.SendAsync(CloneHttpRequestMessage(redirectRequest), HttpCompletionOption.ResponseHeadersRead)).ConfigureAwait(false);

                                try
                                {
                                    return redirectResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                                }
                                finally
                                {
                                    redirectResponse.Dispose();
                                }
                            }
                        }

                        return response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                    }
                    finally
                    {
                        response.Dispose();
                    }
                }
            }
        }

        /// <summary>
        /// Get the last note of the history of comments of the SAST finding.
        /// </summary>
        /// <param name="similarityID"></param>
        /// <param name="projects_ids"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public string GetLastSASTNote(string similarityID, params Guid[] projects_ids)
        {
            if (!projects_ids.Any())
                throw new ArgumentOutOfRangeException(nameof(projects_ids));

            var lastState = SASTResultsPredicates.GetLatestPredicatesBySimilarityIDAsync(similarityID, projects_ids).Result;
            return lastState.LatestPredicatePerProject?.FirstOrDefault()?.Comment;
        }

        private void loadSASTMetadataInfoForScans(params Guid[] projects_ids)
        {
            var scansToRequest = projects_ids.Where(x => !_sastScansMetada.ContainsKey(x));

            if (scansToRequest.Any())
            {
                foreach (var array in SplitArray<Guid>(scansToRequest.ToArray(), 50))
                {
                    var results = SASTMetadata.GetMetadataFromMultipleScansAsync(array).Result;
                    if (results.Scans != null)
                    {
                        foreach (var item in results.Scans)
                            _sastScansMetada.AddOrUpdate(item.ScanId, item, (x, y) => y);
                    }

                    if (results.Missing != null)
                    {
                        foreach (var item in results.Missing)
                            _sastScansMetada.AddOrUpdate((Guid)item, null as ScanInfo, (x, y) => y);
                    }
                }
            }
        }

        public static IEnumerable<T[]> SplitArray<T>(T[] array, int chunkSize)
        {
            for (int i = 0; i < array.Length; i += chunkSize)
            {
                yield return array.Skip(i).Take(chunkSize).ToArray();
            }
        }

        public ScanInfo GetSASTScanInfo(Guid scanId)
        {
            if (scanId == Guid.Empty)
                throw new ArgumentNullException(nameof(scanId));

            loadSASTMetadataInfoForScans(scanId);

            return _sastScansMetada[scanId];
        }

        public bool IsScanIncremental(Guid scanId)
        {
            var sastMetadata = GetSASTScanInfo(scanId);

            if (sastMetadata == null)
                return false;

            return sastMetadata.IsIncremental && !sastMetadata.IsIncrementalCanceled;
        }



        private IDictionary<Guid, Group> _groups = null;
        public IDictionary<Guid, Group> Groups
        {
            get
            {
                if (_groups == null)
                {
                    _groups = AccessManagement.GetGroupsAsync().Result.ToDictionary(x => x.Id);
                }

                return _groups;
            }
        }

        private IDictionary<Guid, User> _users = null;
        public IDictionary<Guid, User> Users
        {
            get
            {
                if (_users == null)
                {
                    _users = AccessManagement.GetUsersAsync().Result.ToDictionary(x => x.Id);
                }

                return _users;
            }
        }

        #endregion

        #region Contributors

        public async Task<IEnumerable<ContributorInsightsGroup>> GetContributorInsightsAsync()
        {
            var url = $"{ASTServer.AbsoluteUri}api/contributors/insights_details";

            using (var request = new HttpRequestMessage(HttpMethod.Get, url))
            {
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                var response = await _retryPolicy.ExecuteAsync(() =>
                    _httpClient.SendAsync(CloneHttpRequestMessage(request), HttpCompletionOption.ResponseHeadersRead));

                response.EnsureSuccessStatusCode();

                var json = await response.Content.ReadAsStringAsync();
                var result = JsonConvert.DeserializeObject<ContributorInsightsResponse>(json);
                return result?.Items ?? Enumerable.Empty<ContributorInsightsGroup>();
            }
        }

        #endregion
    }

}
