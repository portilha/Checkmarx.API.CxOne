using Checkmarx.API.AST.Enums;
using Checkmarx.API.AST.Models.SCA;
using Checkmarx.API.AST.Services.Configuration;
using Checkmarx.API.AST.Services.KicsResults;
using Checkmarx.API.AST.Services.ResultsSummary;
using Checkmarx.API.AST.Services.SASTMetadata;
using Checkmarx.API.AST.Services.SASTResults;
using Checkmarx.API.AST.Services.Scans;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace Checkmarx.API.AST.Models
{
    public class ScanDetails
    {
        private ASTClient _client;
        private Scan _scan;

        public ScanDetails(ASTClient client, Scan scan)
        {
            if (client == null)
                throw new ArgumentNullException(nameof(client));

            if (scan == null)
                throw new ArgumentNullException(nameof(scan));

            _client = client;
            _scan = scan;
        }

        private Dictionary<string, ScanParameter> _scanConfigurations;
        public Dictionary<string, ScanParameter> ScanConfigurations
        {
            get
            {
                if (_scanConfigurations != null) return _scanConfigurations;
                lock (_scanConfigurationsLock)
                {
                    if (_scanConfigurations == null)
                        _scanConfigurations = _client.GetScanConfigurations(_scan.ProjectId, Id);
                }
                return _scanConfigurations;
            }
        }

        public Guid Id => _scan.Id;
        public Guid ProjectId => _scan.ProjectId;
        public Status Status => _scan.Status;
        public DateTimeOffset CreatedAt => _scan.CreatedAt;
        public bool Successful => Status == Status.Completed || Status == Status.Partial;
        public string InitiatorName => _scan.Initiator;
        public string Branch => _scan.Branch;
        public string SourceType => _scan.SourceType;
        public string SourceOrigin => _scan.SourceOrigin;
        public DateTimeOffset? FinishedOn => _scan.UpdatedAt.DateTime;
        public TimeSpan Duration => _scan.UpdatedAt.DateTime - _scan.CreatedAt.DateTime;
        public string Type => _scan.Metadata?.Type;
        public string RepoUrl => _scan.Metadata?.Handler?.GitHandler?.RepoUrl;
        public string UploadUrl => _scan.Metadata?.Handler?.UploadHandler?.UploadUrl;
        public List<string> Engines => _scan.Engines.ToList();

        private readonly object _loadLock = new object();
        private readonly object _scanConfigurationsLock = new object();
        private readonly object _metricsLock = new object();
        private readonly object _languagesLock = new object();
        private readonly object _resultsSummaryLock = new object();
        private readonly object _sastResultsLock = new object();
        private readonly object _sastVulnerabilitiesLock = new object();
        private readonly object _kicsVulnerabilitiesLock = new object();
        private readonly object _sscsVulnerabilitiesLock = new object();
        private readonly object _scaResultsLock = new object();
        private readonly object _scaVulnerabilitiesLock = new object();
        private readonly object _scaRisksLock = new object();
        private readonly object _kicsResultsLock = new object();
        private readonly object _isIncrementalLock = new object();
        private readonly object _engineVersionLock = new object();
        private bool _loaded = false;

        #region SAST

        private Metrics _metrics;
        public Metrics Metrics
        {
            get
            {
                if (_metrics != null) return _metrics;
                lock (_metricsLock)
                {
                    if (_metrics == null)
                        _metrics = _client.SASTMetadata.MetricsAsync(Id).Result;
                }
                return _metrics;
            }
        }

        private string _preset;
        public string Preset
        {
            get
            {
                if (!_loaded && loC == null && string.IsNullOrWhiteSpace(_preset))
                    loadPresetAndLoc();

                return _preset;
            }
            private set => _preset = value;
        }

        private long? loC = null;
        public long LoC
        {
            get
            {
                if (!_loaded && loC == null)
                    loadPresetAndLoc();

                return loC ?? -1;
            }
            private set => loC = value;
        }

        private void loadPresetAndLoc()
        {
            if (_loaded) return;

            lock (_loadLock)
            {
                if (_loaded) return;

                try
                {
                    var sast = _scan.StatusDetails?.SingleOrDefault(x => x.Name == ASTClient.SAST_Engine);
                    if (sast != null)
                        loC = sast.Loc;

                    if (string.IsNullOrWhiteSpace(_preset) && ScanConfigurations.ContainsKey(ASTClient.SettingsProjectPreset))
                        Preset = ScanConfigurations[ASTClient.SettingsProjectPreset].Value;

                    if (loC == null || string.IsNullOrWhiteSpace(_preset))
                    {
                        ScanInfo metadata = _client.SASTMetadata.GetMetadataAsync(Id).Result;
                        if (metadata != null)
                        {
                            Preset = metadata.QueryPreset;
                            LoC = metadata.Loc;
                        }
                    }
                }
                catch (Exception ex)
                {
                    Trace.WriteLine($"Error fetching project {_scan.ProjectId} Preset and LoC. Reason {ex.Message.Replace("\n", " ")}");
                    loC = -1;
                }
                finally
                {
                    _loaded = true;
                }
            }
        }

        private string _languages;
        public string Languages
        {
            get
            {
                if (_languages != null) return _languages;
                lock (_languagesLock)
                {
                    if (_languages == null)
                    {
                        try
                        {
                            // The CxOne API gives 404 when the engines doesn't do anything.
                            var scannedLanguages = Metrics?.ScannedFilesPerLanguage?.Select(x => x.Key);
                            _languages = scannedLanguages != null ? string.Join(";", scannedLanguages) : string.Empty;
                        }
                        catch (Exception)
                        {
                            _languages = string.Empty;
                        }
                    }
                }
                return _languages;
            }
        }

        /// <summary>
        /// Fix this, even if they ask to run as an Incremental it doesn't mean that it ran as incremental...
        /// </summary>
        private bool? _isIncremental;
        public bool IsIncremental
        {
            get
            {
                if (_isIncremental.HasValue) return _isIncremental.Value;
                lock (_isIncrementalLock)
                {
                    if (!_isIncremental.HasValue)
                        _isIncremental = _client.IsScanIncremental(Id);
                }
                return _isIncremental.Value;
            }
        }

        public bool FastConfigurationEnabled
        {
            get
            {
                return ScanConfigurations.ContainsKey(ASTClient.FastScanConfiguration) ?
                    string.Compare(ScanConfigurations[ASTClient.FastScanConfiguration].Value, "true", true) == 0 : false;
            }
        }

        public bool RecommendedExclusionsEnabled
        {
            get
            {
                return ScanConfigurations.ContainsKey(ASTClient.RecommendedExclusionsConfiguration) ?
                 string.Compare(ScanConfigurations[ASTClient.RecommendedExclusionsConfiguration].Value, "true", true) == 0 : false;
            }
        }

        private ResultsSummary _resultsSummary = null;
        private bool _resultsSummaryInitialized = false;
        private ResultsSummary ResultsSummary
        {
            get
            {
                if (_resultsSummaryInitialized) return _resultsSummary;
                lock (_resultsSummaryLock)
                {
                    if (!_resultsSummaryInitialized)
                    {
                        _resultsSummary = _client.GetResultsSummaryById(Id).FirstOrDefault();
                        _resultsSummaryInitialized = true;
                    }
                }
                return _resultsSummary;
            }
        }

        private SASTScanResultDetails _sastResults;
        public SASTScanResultDetails SASTResults
        {
            get
            {
                if (_sastResults != null) return _sastResults;
                lock (_sastResultsLock)
                {
                    if (_sastResults != null) return _sastResults;

                    if (!Successful) return null;

                    var sastStatusDetails = _scan.StatusDetails?.SingleOrDefault(x => x.Name == ASTClient.SAST_Engine);
                    if (sastStatusDetails == null) return null;

                    var result = new SASTScanResultDetails
                    {
                        Id = Id,
                        Status = sastStatusDetails.Status
                    };

                    if (result.Successful)
                        updateSASTScanResultDetails(result);

                    _sastResults = result;
                }
                return _sastResults;
            }
        }

        private List<SASTResult> _sastVulnerabilities;
        public List<SASTResult> SASTVulnerabilities
        {
            get
            {
                if (_sastVulnerabilities != null) return _sastVulnerabilities;
                lock (_sastVulnerabilitiesLock)
                {
                    if (_sastVulnerabilities == null)
                        _sastVulnerabilities = _client.GetSASTScanResultsById(Id, limit: 5000).ToList();
                }
                return _sastVulnerabilities;
            }
        }

        public List<KicsResult> _kicsVulnerabilities;
        public List<KicsResult> KicsVulnerabilities
        {
            get
            {
                if (_kicsVulnerabilities != null) return _kicsVulnerabilities;
                lock (_kicsVulnerabilitiesLock)
                {
                    if (_kicsVulnerabilities == null)
                        _kicsVulnerabilities = _client.GetKicsScanResultsById(Id).ToList();
                }
                return _kicsVulnerabilities;
            }
        }

        public Dictionary<SSCSGroup, IEnumerable<EngineResults>> _sscsVulnerabilities;
        public Dictionary<SSCSGroup, IEnumerable<EngineResults>> SSCSVulnerabilities
        {
            get
            {
                if (_sscsVulnerabilities != null) return _sscsVulnerabilities;
                lock (_sscsVulnerabilitiesLock)
                {
                    if (_sscsVulnerabilities == null)
                        _sscsVulnerabilities = _client.GetSSCSResults(ProjectId, Id);
                }
                return _sscsVulnerabilities;
            }
        }

        public Uri GetSASTResultLink(SASTResult result)
        {
            if (result == null)
                throw new ArgumentNullException(nameof(result));

            return new Uri(_client.ASTServer, $"/sast-results/{ProjectId}/{Id}?resultId={Uri.EscapeDataString(result.ResultHash)}");
        }


        private string _engineVersion;
        public string EngineVersion
        {
            get
            {
                if (_engineVersion != null) return _engineVersion;
                lock (_engineVersionLock)
                {
                    if (_engineVersion == null)
                        _engineVersion = this._client.GetScanEngineVersionAsync([Id]).Result.Values.FirstOrDefault() ?? string.Empty;
                }
                return _engineVersion == string.Empty ? null : _engineVersion;
            }
        }

        #endregion

        #region SCA

        private ScanResultDetails _scaResults = null;
        public ScanResultDetails ScaResults
        {
            get
            {
                if (_scaResults != null) return _scaResults;
                lock (_scaResultsLock)
                {
                    if (_scaResults != null) return _scaResults;

                    if (!Successful) return null;

                    var scaStatusDetails = _scan.StatusDetails.SingleOrDefault(x => x.Name == ASTClient.SCA_Engine);
                    if (scaStatusDetails == null) return null;

                    var result = new ScanResultDetails
                    {
                        Id = Id,
                        Status = scaStatusDetails.Status
                    };

                    if (result.Successful)
                    {
                        updateScaScanResultDetails(
                            result,
                            SCA_Risks,
                            severitySelector: x => x.PendingSeverity,
                            stateSelector: x => x.PendingState
                        );
                    }

                    _scaResults = result;
                }
                return _scaResults;
            }
        }


        private List<Vulnerability> _scaVulnerabilities;
        public List<Vulnerability> SCAVulnerabilities
        {
            get
            {
                if (_scaVulnerabilities != null) return _scaVulnerabilities;
                lock (_scaVulnerabilitiesLock)
                {
                    if (_scaVulnerabilities == null)
                        _scaVulnerabilities = this._client.GetScaScanVulnerabilities(Id, _scaRisks);
                }
                return _scaVulnerabilities;
            }
        }

        private List<ScaVulnerability> _scaRisks;
        public List<ScaVulnerability> SCA_Risks
        {
            get
            {
                if (_scaRisks != null) return _scaRisks;
                lock (_scaRisksLock)
                {
                    if (_scaRisks == null)
                    {
                        _scaRisks = this._client.GraphQLClient.GetAllVulnerabilitiesRisksByScanIdAsync(new VulnerabilitiesRisksByScanIdVariables
                        {
                            ScanId = Id
                        }).Result;
                    }
                }
                return _scaRisks;
            }
        }

        #endregion

        #region KICS

        private ScanResultDetails _kicsResults = null;
        public ScanResultDetails KicsResults
        {
            get
            {
                if (_kicsResults != null) return _kicsResults;
                lock (_kicsResultsLock)
                {
                    if (_kicsResults != null) return _kicsResults;

                    if (!Successful) return null;

                    var kicsStatusDetails = _scan.StatusDetails.SingleOrDefault(x => x.Name == ASTClient.KICS_Engine);
                    if (kicsStatusDetails == null) return null;

                    var result = new ScanResultDetails
                    {
                        Id = Id,
                        Status = kicsStatusDetails.Status
                    };

                    if (result.Successful)
                        updateKicsScanResultDetails(result, _client.GetKicsScanResultsById(Id));

                    _kicsResults = result;
                }
                return _kicsResults;
            }
        }

        #endregion

        #region Update Scan Result Details

        private void updateSASTScanResultDetails(SASTScanResultDetails model)
        {
            var sastResults = SASTVulnerabilities;
            if (sastResults == null)
                return;

            model.Id = Id;

            int total = 0, critical = 0, high = 0, medium = 0, low = 0, info = 0;
            int criticalToVerify = 0, highToVerify = 0, mediumToVerify = 0, lowToVerify = 0;
            int toVerify = 0, notExploitableMarked = 0, pneMarked = 0, otherStates = 0;

            var languages = new HashSet<string>();
            var queriesCritical = new HashSet<string>();
            var queriesHigh = new HashSet<string>();
            var queriesMedium = new HashSet<string>();
            var queriesLow = new HashSet<string>();
            var queriesToVerify = new HashSet<string>();

            foreach (var vuln in sastResults)
            {
                languages.Add(vuln.LanguageName);

                bool isNotInfo = vuln.Severity != ResultsSeverity.INFO;

                if (vuln.State != ResultsState.NOT_EXPLOITABLE.ToString())
                {
                    total++;

                    switch (vuln.Severity)
                    {
                        case ResultsSeverity.CRITICAL:
                            critical++;
                            queriesCritical.Add(vuln.QueryID);
                            if (vuln.State == ResultsState.TO_VERIFY.ToString()) criticalToVerify++;
                            break;
                        case ResultsSeverity.HIGH:
                            high++;
                            queriesHigh.Add(vuln.QueryID);
                            if (vuln.State == ResultsState.TO_VERIFY.ToString()) highToVerify++;
                            break;
                        case ResultsSeverity.MEDIUM:
                            medium++;
                            queriesMedium.Add(vuln.QueryID);
                            if (vuln.State == ResultsState.TO_VERIFY.ToString()) mediumToVerify++;
                            break;
                        case ResultsSeverity.LOW:
                            low++;
                            queriesLow.Add(vuln.QueryID);
                            if (vuln.State == ResultsState.TO_VERIFY.ToString()) lowToVerify++;
                            break;
                        case ResultsSeverity.INFO:
                            info++;
                            break;
                    }

                    if (isNotInfo)
                    {
                        if (vuln.State == ResultsState.TO_VERIFY.ToString())
                        {
                            toVerify++;
                            queriesToVerify.Add(vuln.QueryID);
                        }
                        else if (vuln.State == ResultsState.NOT_EXPLOITABLE.ToString())
                            notExploitableMarked++;
                        else if (vuln.State == ResultsState.PROPOSED_NOT_EXPLOITABLE.ToString())
                            pneMarked++;
                        else
                        {
                            if (vuln.State != ResultsState.CONFIRMED.ToString() && vuln.State != ResultsState.URGENT.ToString())
                                otherStates++;
                        }
                    }
                }
            }

            model.Total = total;
            model.Critical = critical;
            model.High = high;
            model.Medium = medium;
            model.Low = low;
            model.Info = info;

            model.CriticalToVerify = criticalToVerify;
            model.HighToVerify = highToVerify;
            model.MediumToVerify = mediumToVerify;
            model.LowToVerify = lowToVerify;

            model.ToVerify = toVerify;
            model.NotExploitableMarked = notExploitableMarked;
            model.PNEMarked = pneMarked;
            model.OtherStates = otherStates;

            model.LanguagesDetected = languages.ToList();

            model.QueriesCritical = queriesCritical.Count;
            model.QueriesHigh = queriesHigh.Count;
            model.QueriesMedium = queriesMedium.Count;
            model.QueriesLow = queriesLow.Count;
            model.QueriesToVerify = queriesToVerify.Count;
            model.Queries = model.QueriesCritical + model.QueriesHigh + model.QueriesMedium + model.QueriesLow;
        }

        private void updateScaScanResultDetails<T>(
            ScanResultDetails model,
            IEnumerable<T> results,
            Func<T, string> severitySelector,
            Func<T, string> stateSelector)
        {
            var notExploitable = ScaVulnerabilityStatus.NotExploitable.ToString();
            var toVerify = ScaVulnerabilityStatus.ToVerify.ToString();

            var filtered = results.Where(x => stateSelector(x) != notExploitable);

            int total = 0, critical = 0, high = 0, medium = 0, low = 0, info = 0, toVerifyCount = 0;

            foreach (var item in filtered)
            {
                var severity = severitySelector(item)?.ToUpperInvariant();

                total++;

                switch (severity)
                {
                    case "CRITICAL": critical++; break;
                    case "HIGH": high++; break;
                    case "MEDIUM": medium++; break;
                    case "LOW": low++; break;
                    case "INFO": info++; break;
                }

                if (stateSelector(item) == toVerify && severity != "INFO")
                    toVerifyCount++;
            }

            model.Total = total;
            model.Critical = critical;
            model.High = high;
            model.Medium = medium;
            model.Low = low;
            model.Info = info;
            model.ToVerify = toVerifyCount;
        }

        private void updateKicsScanResultDetails(ScanResultDetails model, IEnumerable<KicsResult> results)
        {
            var filtered = results.Where(x => x.State != KicsStateEnum.NOT_EXPLOITABLE.ToString());

            int total = 0, critical = 0, high = 0, medium = 0, low = 0, info = 0, toVerify = 0;

            foreach (var item in filtered)
            {
                total++;

                switch (item.Severity)
                {
                    case Services.KicsResults.SeverityEnum.CRITICAL: critical++; break;
                    case Services.KicsResults.SeverityEnum.HIGH: high++; break;
                    case Services.KicsResults.SeverityEnum.MEDIUM: medium++; break;
                    case Services.KicsResults.SeverityEnum.LOW: low++; break;
                    case Services.KicsResults.SeverityEnum.INFO: info++; break;
                }

                if (item.State == KicsStateEnum.TO_VERIFY.ToString() && item.Severity != Services.KicsResults.SeverityEnum.INFO)
                    toVerify++;
            }

            model.Total = total;
            model.Critical = critical;
            model.High = high;
            model.Medium = medium;
            model.Low = low;
            model.Info = info;
            model.ToVerify = toVerify;
        }

        #endregion

        public TimeSpan GetTimeDurationPerEngine(ScanTypeEnum scanType)
        {
            if (!_scan.Engines.Contains(scanType.ToString()))
                throw new ArgumentException($"{scanType} did not ran in this Scan");

            Checkmarx.API.AST.Services.Scans.StatusDetails status = _scan.StatusDetails.SingleOrDefault(x => x.Name == scanType.ToString());

            TimeSpan value = TimeSpan.Zero;
            if (status != null)
                value = status.Duration;

            if (value == TimeSpan.Zero)
                _scan = _client.Scans.GetScanAsync(Id).Result;

            status = _scan.StatusDetails.SingleOrDefault(x => x.Name == scanType.ToString());

            if (status != null)
                return status.Duration;

            return TimeSpan.Zero;
        }
    }
}
