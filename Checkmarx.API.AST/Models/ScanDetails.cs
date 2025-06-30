using Checkmarx.API.AST.Enums;
using Checkmarx.API.AST.Services;
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
        private Services.Scans.Scan _scan;

        private readonly static string CompletedStage = Checkmarx.API.AST.Services.Scans.Status.Completed.ToString();

        public ScanDetails(ASTClient client, Services.Scans.Scan scan)
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
                if (_scanConfigurations == null)
                    _scanConfigurations = _client.GetScanConfigurations(_scan.ProjectId, Id);

                return _scanConfigurations;
            }
        }

        public Guid Id => _scan.Id;
        public Guid ProjectId => _scan.ProjectId;
        public Status Status => _scan.Status;
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

        #region SAST


        private Metrics _metrics;
        public Metrics Metrics
        {
            get
            {
                if (_metrics == null)
                    _metrics = _client.SASTMetadata.MetricsAsync(Id).Result;

                return _metrics;
            }
        }


        private string preset;
        public string Preset
        {
            get
            {
                if (loC == null)
                    loadPresetAndLoc();

                return preset;
            }
            private set { preset = value; }
        }




        private long? loC = null;

        /// <summary>
        /// Returns the LoC of the SAST Engine.
        /// </summary>
        public long LoC
        {
            get
            {
                if (loC == null)
                {
                    loadPresetAndLoc();
                }
                return loC.Value;
            }
            private set => loC = value;
        }

        private string _languages;
        public string Languages
        {
            get
            {
                if (_languages == null)
                {
                    try
                    {
                        // The CxOne API gives 404 when the engines doesn't do anything.
                        var scannedLanguages = Metrics?.ScannedFilesPerLanguage?.Select(x => x.Key);
                        if (scannedLanguages != null)
                            _languages = string.Join(";", scannedLanguages);
                    }
                    catch (Exception)
                    {
                        _languages = string.Empty;
                    }
                }

                return _languages;
            }
        }

        /// <summary>
        /// Fix this, even if they ask to run as an Incremental it doesn't mean that it ran as incremental...
        /// </summary>
        public bool IsIncremental
        {
            get
            {
                return _client.IsScanIncremental(Id);
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


        private void loadPresetAndLoc()
        {
            try
            {
                if (loC == null)
                {
                    var sast = _scan.StatusDetails?.SingleOrDefault(x => x.Name == ASTClient.SAST_Engine);
                    if (sast != null)
                        loC = sast.Loc;
                }

                if (string.IsNullOrWhiteSpace(preset) && ScanConfigurations.ContainsKey(ASTClient.SettingsProjectPreset))
                    Preset = ScanConfigurations[ASTClient.SettingsProjectPreset].Value;

                if (loC == null || string.IsNullOrWhiteSpace(preset))
                {
                    // Get sast metadata
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
                LoC = -1;
            }
        }

        private ResultsSummary _resultsSummary = null;
        private bool _resultsSummaryInitialized = false;
        private ResultsSummary ResultsSummary
        {
            get
            {
                if (!_resultsSummaryInitialized && _resultsSummary == null)
                {
                    _resultsSummaryInitialized = true;
                    _resultsSummary = _client.GetResultsSummaryById(Id).FirstOrDefault();
                }

                return _resultsSummary;
            }
        }

        private SASTScanResultDetails _sastResults;
        public SASTScanResultDetails SASTResults
        {
            get
            {
                if (_sastResults != null)
                    return _sastResults;

                if (!Successful)
                    return null;

                var sastStatusDetails = _scan.StatusDetails?.SingleOrDefault(x => x.Name == ASTClient.SAST_Engine);
                if (sastStatusDetails == null)
                {
                    return null;
                }

                _sastResults = new SASTScanResultDetails
                {
                    Id = Id,
                    Status = sastStatusDetails.Status
                };

                if (_sastResults.Successful)
                {
                    updateSASTScanResultDetailsBasedOnScanVulnerabilities(_sastResults, Id);
                }

                return _sastResults;
            }
        }

        /// <summary>
        /// Very performance intensive.
        /// </summary>
        /// <param name="scanDetails"></param>
        /// <param name="scanId"></param>
        /// <returns></returns>
        private void updateSASTScanResultDetailsBasedOnScanVulnerabilities(SASTScanResultDetails model, Guid scanId)
        {
            var sastResults = SASTVulnerabilities;
            if (sastResults == null)
                return;

            var results = SASTVulnerabilities.Where(x => x.State != ResultsState.NOT_EXPLOITABLE);

            model.Id = scanId;
            model.Total = results.Count();
            model.Critical = results.Where(x => x.Severity == ResultsSeverity.CRITICAL).Count();
            model.High = results.Where(x => x.Severity == ResultsSeverity.HIGH).Count();
            model.Medium = results.Where(x => x.Severity == ResultsSeverity.MEDIUM).Count();
            model.Low = results.Where(x => x.Severity == ResultsSeverity.LOW).Count();
            model.Info = results.Where(x => x.Severity == ResultsSeverity.INFO).Count();

            model.CriticalToVerify = sastResults.Where(x => x.Severity == ResultsSeverity.CRITICAL && x.State == ResultsState.TO_VERIFY).Count();
            model.HighToVerify = sastResults.Where(x => x.Severity == ResultsSeverity.HIGH && x.State == ResultsState.TO_VERIFY).Count();
            model.MediumToVerify = sastResults.Where(x => x.Severity == ResultsSeverity.MEDIUM && x.State == ResultsState.TO_VERIFY).Count();
            model.LowToVerify = sastResults.Where(x => x.Severity == ResultsSeverity.LOW && x.State == ResultsState.TO_VERIFY).Count();

            var resultsExcludingInfo = results.Where(x => x.Severity != ResultsSeverity.INFO);

            model.ToVerify = resultsExcludingInfo.Where(x => x.State == ResultsState.TO_VERIFY).Count();
            model.NotExploitableMarked = resultsExcludingInfo.Where(x => x.State == ResultsState.NOT_EXPLOITABLE).Count();
            model.PNEMarked = resultsExcludingInfo.Where(x => x.State == ResultsState.PROPOSED_NOT_EXPLOITABLE).Count();
            model.OtherStates = resultsExcludingInfo.Where(x =>
                                                        x.State != ResultsState.CONFIRMED &&
                                                        x.State != ResultsState.URGENT &&
                                                        x.State != ResultsState.NOT_EXPLOITABLE &&
                                                        x.State != ResultsState.PROPOSED_NOT_EXPLOITABLE &&
                                                        x.State != ResultsState.TO_VERIFY).Count();
            model.LanguagesDetected = sastResults.Select(x => x.LanguageName).Distinct().ToList();
            //model.Queries = report.ScanResults.Sast.Languages.Sum(x => x.Queries.Count());

            try
            {
                // Scan query categories
                var scanResultsCritical = results.Where(x => x.Severity == ResultsSeverity.CRITICAL);
                var scanResultsHigh = results.Where(x => x.Severity == ResultsSeverity.HIGH);
                var scanResultsMedium = results.Where(x => x.Severity == ResultsSeverity.MEDIUM);
                var scanResultsLow = results.Where(x => x.Severity == ResultsSeverity.LOW);

                var scanQueriesCritical = scanResultsCritical.Select(x => x.QueryID).Distinct().ToList();
                var scanQueriesHigh = scanResultsHigh.Select(x => x.QueryID).Distinct().ToList();
                var scanQueriesMedium = scanResultsMedium.Select(x => x.QueryID).Distinct().ToList();
                var scanQueriesLow = scanResultsLow.Select(x => x.QueryID).Distinct().ToList();

                model.QueriesCritical = scanQueriesCritical.Count();
                model.QueriesHigh = scanQueriesHigh.Count();
                model.QueriesMedium = scanQueriesMedium.Count();
                model.QueriesLow = scanQueriesLow.Count();
                model.Queries = model.QueriesCritical + model.QueriesHigh + model.QueriesMedium + model.QueriesLow;
            }
            catch
            {
                model.QueriesCritical = null;
                model.QueriesHigh = null;
                model.QueriesMedium = null;
                model.QueriesLow = null;
            }
        }

        private List<SASTResult> _sastVulnerabilities;
        public List<SASTResult> SASTVulnerabilities
        {
            get
            {
                if (_sastVulnerabilities == null)
                    _sastVulnerabilities = _client.GetSASTScanResultsById(Id, limit: 5000).ToList();

                return _sastVulnerabilities;
            }
        }

        #endregion

        #region SCA

        public ScanResultDetails _scaResults = null;
        public ScanResultDetails ScaResults
        {
            get
            {
                if (_scaResults != null)
                    return _scaResults;

                if (!Successful)
                    return null;

                var scaStatusDetails = _scan.StatusDetails.SingleOrDefault(x => x.Name == ASTClient.SCA_Engine);
                if (scaStatusDetails == null)
                {
                    return null;
                }

                _scaResults = new ScanResultDetails
                {
                    Id = Id,
                    Status = scaStatusDetails.Status
                };

                if (_scaResults.Successful)
                    updateScaScanResultDetailsBasedOnResultsSummary(_scaResults);

                return _scaResults;
            }
        }


        private List<Vulnerability> _scaVulnerabilities;

        public List<Vulnerability> SCAVulnerabilities
        {
            get
            {
                if (_scaVulnerabilities == null)
                {
                    ScanReportJson lastScanReport = this._client.Requests.GetScanReport(Id);
                    _scaVulnerabilities = lastScanReport.Vulnerabilities;
                }

                return _scaVulnerabilities;
            }

        }

        private void updateScaScanResultDetailsBasedOnResultsSummary(ScanResultDetails model)
        {
            var scaResults = SCAVulnerabilities;
            if (scaResults == null)
                return;

            var results = SCAVulnerabilities.Where(x => x.RiskState != VulnerabilityStatus.NotExploitable);

            model.Total = results.Count();
            model.Critical = results.Where(x => x.Severity.ToUpper() == Services.KicsResults.SeverityEnum.CRITICAL.ToString()).Count();
            model.High = results.Where(x => x.Severity.ToUpper() == Services.KicsResults.SeverityEnum.HIGH.ToString()).Count();
            model.Medium = results.Where(x => x.Severity.ToUpper() == Services.KicsResults.SeverityEnum.MEDIUM.ToString()).Count();
            model.Low = results.Where(x => x.Severity.ToUpper() == Services.KicsResults.SeverityEnum.LOW.ToString()).Count();
            model.Info = results.Where(x => x.Severity.ToUpper() == Services.KicsResults.SeverityEnum.INFO.ToString()).Count();

            model.ToVerify = results.Where(x => x.RiskState == VulnerabilityStatus.ToVerify &&
                                                x.Severity.ToUpper() != Services.KicsResults.SeverityEnum.INFO.ToString()).Count();
        }

        #endregion

        #region KICS

        public ScanResultDetails _kicsResults = null;
        public ScanResultDetails KicsResults
        {
            get
            {
                if (_kicsResults != null)
                    return _kicsResults;

                if (!Successful)
                    return null;

                var kicsStatusDetails = _scan.StatusDetails.SingleOrDefault(x => x.Name == ASTClient.KICS_Engine);
                if (kicsStatusDetails == null)
                {
                    return null;
                }

                _kicsResults = new ScanResultDetails
                {
                    Id = Id,
                    Status = kicsStatusDetails.Status
                };

                if (_kicsResults.Successful)
                    updateKicsScanResultDetailsBasedOnKicsVulnerabilities(_kicsResults, Id);

                return _kicsResults;
            }
        }

        private void updateKicsScanResultDetailsBasedOnKicsVulnerabilities(ScanResultDetails model, Guid scanId)
        {
            var kicsResults = _client.GetKicsScanResultsById(scanId);
            if (kicsResults == null)
            {
                return;
            }

            var results = kicsResults.Where(x => x.State != KicsStateEnum.NOT_EXPLOITABLE);

            model.Id = scanId;
            model.Total = results.Count();
            model.Critical = results.Where(x => x.Severity == Services.KicsResults.SeverityEnum.CRITICAL).Count();
            model.High = results.Where(x => x.Severity == Services.KicsResults.SeverityEnum.HIGH).Count();
            model.Medium = results.Where(x => x.Severity == Services.KicsResults.SeverityEnum.MEDIUM).Count();
            model.Low = results.Where(x => x.Severity == Services.KicsResults.SeverityEnum.LOW).Count();
            model.Info = results.Where(x => x.Severity == Services.KicsResults.SeverityEnum.INFO).Count();
            model.ToVerify = kicsResults.Where(x => x.State == KicsStateEnum.TO_VERIFY && x.Severity != Services.KicsResults.SeverityEnum.INFO).Count();
        }

        #endregion

        public TimeSpan GetTimeDurationPerEngine(ScanTypeEnum scanType)
        {
            if (!_scan.Engines.Contains(scanType.ToString()))
                throw new ArgumentException($"{scanType} did not ran in this Scan");

            var value = _scan.StatusDetails.Single(x => x.Name == scanType.ToString()).Duration;

            if (value == TimeSpan.Zero)
                _scan = _client.Scans.GetScanAsync(Id).Result;

            value = _scan.StatusDetails.Single(x => x.Name == scanType.ToString()).Duration;

            return value;
        }
    }
}
