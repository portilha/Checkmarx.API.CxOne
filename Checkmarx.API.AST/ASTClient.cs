using Checkmarx.API.AST.Enums;
using Checkmarx.API.AST.Services.Applications;
using Checkmarx.API.AST.Services.Audit;
using Checkmarx.API.AST.Services.Projects;
using Checkmarx.API.AST.Services.Scans;
using Checkmarx.API.AST.Services.SASTResults;
using Checkmarx.API.AST.Services.Reports;
using Checkmarx.API.AST.Services.SASTMetadata;
using Checkmarx.API.AST.Models;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using Checkmarx.API.AST.Models.Report;

namespace Checkmarx.API.AST
{
    public class ASTClient
    {
        public Uri AcessControlServer { get; private set; }
        public Uri ASTServer { get; private set; }
        public string Tenant { get; }
        public string KeyApi { get; set; }

        private readonly HttpClient _httpClient = new HttpClient();

        private DateTime _bearerValidTo;

        private Projects _projects;
        public Projects Projects
        {
            get {
                if (_projects == null && Connected)
                    _projects = new Projects(_httpClient)
                    {
                        BaseUrl = $"{ASTServer.AbsoluteUri}api/projects"
                    };

                return _projects;  
            }
        }

        private Scans _scans;
        public Scans Scans
        {
            get
            {
                if (_scans == null && Connected)
                    _scans = new Scans(_httpClient)
                    {
                        BaseUrl = $"{ASTServer.AbsoluteUri}api/scans"
                    };

                return _scans;
            }
        }

        private Reports _reports;
        public Reports Reports
        {
            get
            {
                if (_reports == null && Connected)
                    _reports = new Reports(_httpClient)
                    {
                        BaseUrl = $"{ASTServer.AbsoluteUri}api/reports"
                    };

                return _reports;
            }
        }

        private SASTMetadata _SASTMetadata;
        public SASTMetadata SASTMetadata
        {
            get
            {
                if (_SASTMetadata == null && Connected)
                    _SASTMetadata = new SASTMetadata(_httpClient)
                    {
                        BaseUrl = $"{ASTServer.AbsoluteUri}api/sast-metadata"
                    };

                return _SASTMetadata;
            }
        }

        private Applications _applications;
        public Applications Applications
        {
            get
            {
                if (_applications == null && Connected)
                    _applications = new Applications(_httpClient)
                    {
                        BaseUrl = $"{ASTServer.AbsoluteUri}api/applications"
                    };

                return _applications;
            }
        }

        private Audit _audit;
        public Audit Audit
        {
            get
            {
                if (_audit == null && Connected)
                    _audit = new Audit(_httpClient)
                    {
                        BaseUrl = $"{ASTServer.AbsoluteUri}api/audit"
                    };

                return _audit;
            }
        }

        // Engine SAST results
        private SASTResults _SASTResults;
        public SASTResults SASTResults
        {
            get
            {
                if (_SASTResults == null && Connected)
                    _SASTResults = new SASTResults($"{ASTServer.AbsoluteUri}api/sast-results", _httpClient);

                return _SASTResults;
            }
        }

        

        public bool Connected
        {
            get
            {
                if (_httpClient == null || (_bearerValidTo - DateTime.UtcNow).TotalMinutes < 5)
                {
                    var token = Autenticate();
                    _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
                    _bearerValidTo = DateTime.UtcNow.AddHours(1);
                }
                return true;
            }
        }

        private void checkConnection()
        {
            if (!Connected)
                throw new NotSupportedException();
        }

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
        public ASTClient(Uri astServer, Uri acessControlServer, string tenant, string apiKey)
        {
            if (astServer == null) throw new ArgumentNullException(nameof(astServer));
            if (acessControlServer == null) throw new ArgumentNullException(nameof(acessControlServer));
            if (string.IsNullOrWhiteSpace(tenant)) throw new ArgumentNullException(nameof(tenant));
            if (string.IsNullOrWhiteSpace(apiKey)) throw new ArgumentNullException(nameof(apiKey));

            ASTServer = astServer;
            AcessControlServer = acessControlServer;
            Tenant = tenant;
            KeyApi = apiKey;
        }

        private string Autenticate()
        {
            var identityURL = $"{AcessControlServer.AbsoluteUri}auth/realms/{Tenant}/protocol/openid-connect/token";
            var kv = new Dictionary<string, string>
            {
                { "grant_type", "refresh_token" },
                { "client_id", "ast-app" },
                { "refresh_token", $"{KeyApi}" }
            };

            var req = new HttpRequestMessage(HttpMethod.Post, identityURL) { Content = new FormUrlEncodedContent(kv) };
            var response = _httpClient.SendAsync(req).Result;
            if (response.StatusCode == System.Net.HttpStatusCode.OK)
            {
                JObject accessToken = JsonConvert.DeserializeObject<JObject>(response.Content.ReadAsStringAsync().Result);
                string authToken = ((JProperty)accessToken.First).Value.ToString();
                return authToken;
            }
            throw new Exception(response.Content.ReadAsStringAsync().Result);
        }

        #region Audit

        /// <summary>
        /// Retrieves all audit events for the given date range, including events stored in
        /// the daily archive links returned by the API.
        /// </summary>
        /// <param name="from">Start date in YYYY-MM-DD format. Cannot be more than 365 days in the past.</param>
        /// <param name="to">End date in YYYY-MM-DD format.</param>
        /// <returns>Combined list of all audit events from both the inline response and every archive link.</returns>
        public IList<Checkmarx.API.AST.Services.Audit.AuditEvent> GetAllAuditEvents(string from = null, string to = null)
        {
            checkConnection();

            var result = Audit.GetAuditEventsAsync(from, to).Result;
            var allEvents = new List<Checkmarx.API.AST.Services.Audit.AuditEvent>();

            if (result.Links != null)
            {
                foreach (var link in result.Links)
                {
                    if (string.IsNullOrEmpty(link.Url))
                        continue;

                    var json = Audit.DownloadLinkAsync(link.Url).Result;
                    if (!string.IsNullOrEmpty(json))
                    {
                        var events = JsonConvert.DeserializeObject<List<Checkmarx.API.AST.Services.Audit.AuditEvent>>(json);
                        if (events != null)
                            allEvents.AddRange(events);
                    }
                }
            }

            if (result.Events != null)
                allEvents.AddRange(result.Events);

            return allEvents;
        }

        #endregion

        #region Projects

        public ProjectsCollection GetAllProjectsDetails(bool showAlsoDeletedProjects = false)
        {
            checkConnection();

            //return Projects.GetListOfProjectsAsync(200).Result;

            var getLimit = 20;

            var listProjects = Projects.GetListOfProjectsAsync(getLimit).Result;
            if (listProjects.TotalCount > getLimit)
            {
                var offset = getLimit;
                bool cont = true;
                do
                {
                    var next = Projects.GetListOfProjectsAsync(getLimit, offset).Result;
                    if (next.Projects.Any())
                    {
                        next.Projects.ToList().ForEach(o => listProjects.Projects.Add(o));
                        offset += getLimit;

                        if(listProjects.Projects.Count == listProjects.TotalCount) cont = false;
                    }
                    else
                        cont = false;

                } while (cont);
            }

            return listProjects;
        }

        public void UpdateProjectStatus(string projectId, string status)
        {
            var proj = Projects.GetProjectAsync(projectId).Result;
            if(proj != null)
            {
                var tags = proj.Tags;
                if (tags.ContainsKey("asa_status"))
                    tags["asa_status"] = status;
                else
                    tags.Add("asa_status", status);

                // temporary to clean old status
                if (tags.ContainsKey("status"))
                    tags.Remove("status");

                Projects.UpdateProjectAsync(projectId, new ProjectInput { Tags = tags }).Wait();
            }
        }

        #endregion


        #region Scans

        public IEnumerable<Checkmarx.API.AST.Models.Scan> GetAllSASTScans(Guid projectId)
        {
            return GetScans(projectId, true, ScanRetrieveKind.All);
        }

        public Checkmarx.API.AST.Models.Scan GetLastScan(Guid projectId)
        {
            var scan = GetScans(projectId, true, ScanRetrieveKind.Last);
            return scan.FirstOrDefault();
        }

        public Checkmarx.API.AST.Models.Scan GetLockedScan(Guid projectId)
        {
            return GetScans(projectId, true, ScanRetrieveKind.Locked).FirstOrDefault();
        }

        public List<Checkmarx.API.AST.Models.Scan> GetScans(Guid projectId, bool finished,
            ScanRetrieveKind scanKind = ScanRetrieveKind.All)
        {
            List<Models.Scan> list = new List<Models.Scan>();

            checkConnection();

            var scanList = Scans.GetListOfScansAsync(projectId.ToString()).Result;
            var scans = scanList.Scans.Select(x => x);
            if (scans.Any())
            {
                //if (version != null)
                //    scans = scans.Where(x => version.StartsWith(x.ProductVersion));

                switch (scanKind)
                {
                    case ScanRetrieveKind.First:
                        scans = scans.Take(1);
                        break;
                    case ScanRetrieveKind.Last:
                        scans = scans.Skip(Math.Max(0, scans.Count() - 1));
                        break;
                    case ScanRetrieveKind.All:
                        break;
                }

                foreach (var scan in scans)
                {
                    list.Add(Models.Scan.FromJson(JsonConvert.SerializeObject(scan)));
                }
            }

            return list;
        }

        public ScanDetails GetScanDetails(string projectId, string scanId, DateTime createdAt)
        {
            try
            {
                var report = GetAstScanJsonReport(projectId, scanId);
                var metadata = SASTMetadata.GetMetadataAsync(new Guid(scanId)).Result;

                ScanDetails result = new ScanDetails();
                result.Id = new Guid(scanId);

                if (metadata != null)
                {
                    result.Preset = metadata.QueryPreset;
                    result.LoC = metadata.Loc;
                }

                if (report != null)
                {
                    var split = report.ScanSummary.ScanCompletedDate.Split(" ");
                    DateTime startedOn = createdAt;
                    DateTime endOn = Convert.ToDateTime($"{split[0]} {split[1]}");

                    result.FinishedOn = startedOn;
                    result.Duration = endOn - startedOn;

                    if (report.ScanSummary.Languages != null && report.ScanSummary.Languages.Any())
                        result.Languages = string.Join(";", report.ScanSummary.Languages.Where(x => x != "Common").Select(x => x).ToList());

                    //Scan Results
                    if (report.ScanResults.Sast != null)
                    {
                        result.SASTResults = new ScanResultDetails
                        {
                            Total = (uint)Convert.ToInt32(report.ScanResults.Sast.Vulnerabilities.Total),
                            High = (uint)Convert.ToInt32(report.ScanResults.Sast.Vulnerabilities.High),
                            Medium = (uint)Convert.ToInt32(report.ScanResults.Sast.Vulnerabilities.Medium),
                            Low = (uint)Convert.ToInt32(report.ScanResults.Sast.Vulnerabilities.Low),
                            Info = (uint)Convert.ToInt32(report.ScanResults.Sast.Vulnerabilities.Info),
                            Queries = report.ScanResults.Sast.Languages.Sum(x => x.Queries.Count()),
                        };

                        if (report.ScanResults.Sast.Languages != null && report.ScanResults.Sast.Languages.Any())
                            result.SASTResults.LanguagesDetected = report.ScanResults.Sast.Languages.Where(x => x.LanguageName != "Common").Select(x => x.LanguageName).ToList();
                    }

                    if (report.ScanResults.Sca != null)
                    {
                        result.ScaResults = new ScanResultDetails
                        {
                            Total = (uint)Convert.ToInt32(report.ScanResults.Sca.Vulnerabilities.Total),
                            High = (uint)Convert.ToInt32(report.ScanResults.Sca.Vulnerabilities.High),
                            Medium = (uint)Convert.ToInt32(report.ScanResults.Sca.Vulnerabilities.Medium),
                            Low = (uint)Convert.ToInt32(report.ScanResults.Sca.Vulnerabilities.Low),
                            Info = (uint)Convert.ToInt32(report.ScanResults.Sca.Vulnerabilities.Info)
                        };
                    }

                    if (report.ScanResults.Kics != null)
                    {
                        result.KicsResults = new ScanResultDetails
                        {
                            Total = (uint)Convert.ToInt32(report.ScanResults.Kics.Vulnerabilities.Total),
                            High = (uint)Convert.ToInt32(report.ScanResults.Kics.Vulnerabilities.High),
                            Medium = (uint)Convert.ToInt32(report.ScanResults.Kics.Vulnerabilities.Medium),
                            Low = (uint)Convert.ToInt32(report.ScanResults.Kics.Vulnerabilities.Low),
                            Info = (uint)Convert.ToInt32(report.ScanResults.Kics.Vulnerabilities.Info)
                        };
                    }
                }

                return result;
            }
            catch (Exception)
            {
                return null;
            }
        }

        private ReportResults GetAstScanJsonReport(string projectId, string scanId)
        {
            ScanReportCreateInput sc = new ScanReportCreateInput();
            sc.ReportName = BaseReportCreateInputReportName.ScanReport;
            sc.ReportType = BaseReportCreateInputReportType.Cli;
            sc.FileFormat = BaseReportCreateInputFileFormat.Json;
            sc.Data = new Data { ProjectId = projectId, ScanId = scanId };

            var createReportOutut = Reports.CreateReportAsync(sc).Result;
            if (createReportOutut != null)
            {
                var createReportId = createReportOutut.ReportId;
                if (createReportId != null)
                {
                    string downloadUrl = null;
                    Guid reportId = createReportId;
                    string reportStatus = "Requested";
                    string pastReportStatus = reportStatus;
                    //Logging.LogManager.AppendLog(Logging.LogManager.LogSource.Worker, "Waiting/pooling for AST json report, please wait...");
                    double aprox_seconds_passed = 0.0;
                    while (reportStatus != "Completed")
                    {
                        System.Threading.Thread.Sleep(2000);
                        aprox_seconds_passed += 2.020;
                        var statusResponse = Reports.GetReportAsync(reportId, true).GetAwaiter().GetResult();
                        reportId = statusResponse.ReportId;
                        reportStatus = statusResponse.Status.ToString();
                        downloadUrl = statusResponse.Url;
                        if (reportStatus != "Requested" && reportStatus != "Completed" && reportStatus != "Started" && reportStatus != "Failed")
                        {
                            //Logging.LogManager.AppendLog(Logging.LogManager.LogSource.Worker, "Abnormal AST json report status! You may want to [cancel all] and retry.");
                        }
                        if (pastReportStatus != reportStatus)
                        {
                            pastReportStatus = reportStatus;
                        }
                        if (aprox_seconds_passed > 15.0 * 60.0)
                        {
                            //Logging.LogManager.AppendLog(Logging.LogManager.LogSource.Worker, "AST json report is taking a long time! You may want to [cancel all] and retry.");
                        }
                        if (reportStatus == "Failed")
                        {
                            //Logging.LogManager.AppendLog(Logging.LogManager.LogSource.Worker, "AST API says it could not generate a json report. You may want to [cancel all] and retry with diferent scans.");
                            return null;
                        }
                    }

                    var reportString = Reports.DownloadScanReportJsonUrl(downloadUrl).GetAwaiter().GetResult();

                    return JsonConvert.DeserializeObject<ReportResults>(reportString);
                }
                else
                {
                    //Dbug.wline($"Error getting Report of Scan {scanId}");
                }
            }

            return null;
        }

        #endregion
    }
}
