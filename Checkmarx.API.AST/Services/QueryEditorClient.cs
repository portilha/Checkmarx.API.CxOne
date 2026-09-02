using Checkmarx.API.AST.Services.QueryEditor;
using Polly;
using Polly.Extensions.Http;
using Polly.Timeout;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using static Checkmarx.API.AST.ASTClient;

namespace Checkmarx.API.AST
{
    /// <summary>
    /// Owns every operation that goes through CxOne's query editor session API — create/read/update/
    /// delete for Tenant/Project/Application-level queries — plus the session lifecycle underneath: the
    /// tenant-wide slot budget, retrying session creation, and cleaning up sessions this client decides
    /// not to use.
    ///
    /// Extracted out of ASTClient (which keeps only the plain, sessionless query listing methods —
    /// GetQueries, GetAllQueries, GetCxLevelQueries, GetTenantLevelQueries, GetProjectLevelQueries) for
    /// two reasons: this had grown into a large, independently fragile subsystem in its own right
    /// (extensive debugging history around session-limit error 776), and it needed its own retry
    /// policy — tuned for the specific, now-understood ways session creation can fail — separate from
    /// the plain transient-retry policy every other ASTClient-backed service uses.
    ///
    /// ASTClient keeps every one of these methods' original public signatures as one-line delegates to
    /// an instance of this class, so no caller anywhere else in the solution needed to change.
    /// </summary>
    internal class QueryEditorClient
    {
        private readonly ASTClient _client;
        private readonly HttpClient _httpClient;

        internal QueryEditorClient(ASTClient client, HttpClient httpClient)
        {
            _client = client ?? throw new ArgumentNullException(nameof(client));
            _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        }

        private QueryEditor _queryEditor;
        private QueryEditor QueryEditor
        {
            get
            {
                if (_client.Connected && _queryEditor == null)
                    _queryEditor = new QueryEditor($"{_client.ASTServer.AbsoluteUri}api/query-editor", _httpClient);

                return _queryEditor;
            }
        }

        #region Session budget and retry policy

        // Tenant-wide limit is 5 concurrent sessions (shared with UI users). 3 is safe for automation.
        // Keyed per tenant (not one global gate) — a process juggling multiple ASTClient instances
        // (e.g. a migration's source + target tenant) must not have them fight over the same budget;
        // each tenant has its own independent 5-slot cap on the server.
        internal const int MaxConcurrentSessions = 3;
        private static readonly ConcurrentDictionary<string, SemaphoreSlim> _querySessionGates = new ConcurrentDictionary<string, SemaphoreSlim>();

        // How long a caller will wait in line for one of the 3 slots above before giving up. This is
        // queueing time, not a sign of trouble: callers that fetch source code for every query in the
        // tenant (not just overrides) can have dozens of language groups all dispatched at once, each
        // starting its own countdown — with only 3 concurrent slots, a group queued behind several
        // others can easily need 15-20+ minutes of real wall-clock time to reach its turn even though
        // nothing is actually stuck. 10 minutes was tuned for the old override-only workload (a
        // handful of groups, short queue) and was observed timing out most of a run's language groups
        // (Python, PHP, Objc, Perl, PLSQL, RPG) the moment a full-catalog fetch made the queue deep —
        // the whole run still finished a few minutes after the 10-minute mark, meaning those groups
        // would very likely have succeeded had they simply been allowed to keep waiting.
        private static readonly TimeSpan _querySessionAcquireTimeout = TimeSpan.FromMinutes(45);

        private SemaphoreSlim querySessionGate =>
            _querySessionGates.GetOrAdd($"{_client.ASTServer}|{_client.Tenant}", _ => new SemaphoreSlim(MaxConcurrentSessions, MaxConcurrentSessions));

        // There is no server-side endpoint left to pre-check session availability (the legacy
        // cx-audit /sessions endpoint has been decommissioned), so contention from other
        // users/processes on the tenant can only be detected by a failed session creation.
        private const int _querySessionCreateMaxAttempts = 3;
        private static readonly TimeSpan _querySessionCreateRetryDelay = TimeSpan.FromSeconds(30);

        // How long checkSessionStatusAndGetId will poll a session's provisioning status before giving
        // up. Without this, a session whose server-side indexing job never reaches a terminal status
        // (Finished/Failed/Canceled) would poll forever — silently holding both our own
        // querySessionGate slot and the real server-side session slot hostage for the rest of the
        // process's lifetime, since nothing else times out that specific wait.
        private static readonly TimeSpan _sessionProvisioningTimeout = TimeSpan.FromMinutes(5);

        // Purely diagnostic: QueryEditor.cs's generated methods all call
        // QueryEditorClient._retryPolicy.ExecuteAsync(() => client_.SendAsync(...)) with no Context, so
        // the shared onRetry callback below has no idea which request it's retrying — every "Transient
        // retry" line would otherwise look identical no matter which endpoint, session, or query is
        // actually failing. QueryEditor.Diagnostics.cs's PrepareRequest hook sets this immediately
        // before each SendAsync call, so it reflects "the request currently being attempted" for that
        // logical call chain. AsyncLocal, not a plain field: each concurrent call (one per
        // Parallel.ForEach task) gets its own value with no cross-talk between the sessions running at
        // once, and a set doesn't leak back up to the caller once the request completes.
        internal static readonly AsyncLocal<string> _currentRequestDescription = new AsyncLocal<string>();

        // Which project/language a session (and every QueryEditor call made against it — create, get
        // queries, check status, delete) belongs to. The URL alone (POST sessions) can't say this — the
        // project/scan/language live in the request body — so PrepareRequest folds this into
        // _currentRequestDescription instead. Needed to tell "error 776 always on a fresh project" apart
        // from "error 776 specifically on a project a session was already opened for earlier in this run"
        // — the two point at very different root causes.
        internal static readonly AsyncLocal<string> _currentSessionSubject = new AsyncLocal<string>();

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

            // CxOne's own error code for "the maximum number of query editor sessions has been
            // reached" (returned as a 500 with this code in the body — see readBodySnippetAndDispose).
            const string SessionLimitReachedErrorCode = "776";

            // Transient/429 retry policy, with error-776-aware pacing
            var transientRetryPolicy = HttpPolicyExtensions
                .HandleTransientHttpError()
                .OrResult(r => r.StatusCode == System.Net.HttpStatusCode.TooManyRequests)
                .WaitAndRetryAsync(
                    10,
                    (int retryAttempt, DelegateResult<HttpResponseMessage> outcome, Context context) =>
                    {
                        // The response body can only be read once — every call site sends with
                        // HttpCompletionOption.ResponseHeadersRead, so the body is still a live,
                        // unbuffered stream at this point — so it's read exactly here (and disposed)
                        // and stashed in Context for the onRetry callback below to log, rather than
                        // read a second time there.
                        string bodySnippet = readBodySnippetAndDispose(outcome.Result);
                        context["BodySnippet"] = bodySnippet;

                        // Error 776 is not the kind of fleeting blip the exponential backoff below is
                        // tuned for — a session only frees up once someone else's closes (or its own
                        // server-side timeout elapses), so retrying every few seconds just adds noise
                        // and load for no benefit. Wait a fixed, longer interval instead, with wider
                        // jitter so our own concurrent callers — all sharing the same querySessionGate,
                        // so all hitting this at the same moment — don't retry in lockstep.
                        if (bodySnippet != null && bodySnippet.Contains($"\"code\":\"{SessionLimitReachedErrorCode}\""))
                            return TimeSpan.FromSeconds(20) + TimeSpan.FromMilliseconds(Random.Shared.Next(0, 5000));

                        return TimeSpan.FromSeconds(Math.Min(Math.Pow(2, retryAttempt), 30)) +
                            TimeSpan.FromMilliseconds(Random.Shared.Next(0, 1000));
                    },
                    (DelegateResult<HttpResponseMessage> outcome, TimeSpan timeSpan, int retryCount, Context context) =>
                    {
                        string requestDescription = _currentRequestDescription.Value;
                        string bodySnippet = context.TryGetValue("BodySnippet", out var b) ? b as string : null;
                        Console.WriteLine(
                            $"Transient retry {retryCount}/10 after {timeSpan.TotalSeconds:F1}s. " +
                            $"Reason: {(outcome.Exception != null ? outcome.Exception.Message : $"{(int?)outcome.Result?.StatusCode} {outcome.Result?.ReasonPhrase}")}" +
                            (string.IsNullOrEmpty(requestDescription) ? "" : $" | {requestDescription}") +
                            (string.IsNullOrEmpty(bodySnippet) ? "" : $" | Body: {bodySnippet}"));
                        return Task.CompletedTask;
                    });

            // Wrap order matters:
            // transientRetryPolicy (outermost) → timeoutRetryPolicy → timeoutPolicy (innermost)
            return Policy.WrapAsync(transientRetryPolicy, timeoutRetryPolicy, timeoutPolicy);
        }

        // Reads a snippet of a failed attempt's body for diagnostics — the generic "500 Internal
        // Server Error" reason phrase alone can't tell a session-limit response apart from any other
        // server error, and the CxOne API has been observed to return a specific error code in the
        // body for at least one other known 500 case. Also disposes the response: Polly does not
        // dispose the HttpResponseMessage of a retried (discarded) attempt on its own, so this is the
        // only place that ever would.
        private static string readBodySnippetAndDispose(HttpResponseMessage response)
        {
            if (response == null)
                return null;

            try
            {
                string body = response.Content?.ReadAsStringAsync().GetAwaiter().GetResult();
                if (string.IsNullOrWhiteSpace(body))
                    return null;

                body = body.Trim();
                return body.Length > 500 ? body.Substring(0, 500) + "..." : body;
            }
            catch
            {
                // A failed body read must never mask the retry itself.
                return null;
            }
            finally
            {
                response.Dispose();
            }
        }

        #endregion

        /// <summary>
        /// Get the Query Source by language and name
        /// </summary>
        /// <param name="language">The query language</param>
        /// <param name="queryName">The query name</param>
        /// <param name="projectId">The ID of the project to retrieve queries for.</param>
        /// <param name="scanId">The ID of the scan to create a session</param>
        /// <returns>The query source</returns>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="Exception"></exception>
        public string GetQuerySource(string language, string queryName, Guid? projectId = null, Guid? scanId = null)
        {
            if (string.IsNullOrWhiteSpace(language))
                throw new ArgumentException(nameof(language));

            if (string.IsNullOrWhiteSpace(queryName))
                throw new ArgumentException(nameof(queryName));

            string level = Query_Level_Tenant;
            if (projectId.HasValue)
                level = Query_Level_Project;

            var session = getQueryEditorSessionKey(level, language, projectId, scanId);

            try
            {
                var query = getQueryByLanguageAndName(session, language, queryName);

                if (query == null)
                    throw new Exception($"No query found for language {language} with the name {queryName}");

                return query.Source;
            }
            finally { endQueryEditorSession(session); }
        }

        /// <summary>
        /// Overrides a query at a project level
        /// </summary>
        /// <param name="projectId">The ID of the project to overwrite the query for.</param>
        /// <param name="language">Query language (case insensitive)</param>
        /// <param name="queryName">Query Name (case insensitive)</param>
        /// <param name="querySource">Query Source</param>
        /// <param name="scanId">The ID of the scan to create a session</param>
        /// <returns>Returns the query editor key</returns>
        /// <exception cref="Exception"></exception>
        public void OverrideProjectQuerySource(Guid projectId, string language, string queryName, string querySource, Guid? scanId = null)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentNullException(nameof(projectId));

            if (string.IsNullOrWhiteSpace(language))
                throw new ArgumentException(nameof(language));

            if (string.IsNullOrWhiteSpace(queryName))
                throw new ArgumentException(nameof(queryName));

            if (string.IsNullOrWhiteSpace(querySource))
                throw new ArgumentException(nameof(querySource));

            var session = getQueryEditorSessionKey(Query_Level_Project, language, projectId, scanId);

            try
            {
                var query = getQueryByLanguageAndName(session, language, queryName);

                if (query == null)
                    throw new Exception($"No query found for language {language} with the name {queryName} for project {projectId}");

                // If there is an existing query at the project level already, call the method to update the source code
                // If not, create the new query
                if (query.Level == Query_Level_Project)
                {
                    // Do not update the source code if there is no differences. API will throw an error "error modifying query environment"
                    if (query.Source != querySource)
                        updateQuerySourceByEditorQuery(session, query.Id, querySource);
                }
                else
                {
                    createQuery(session, query, Query_Level_Project, querySource);
                }
            }
            finally { endQueryEditorSession(session); }
        }

        // The write payload for an Application-level override was observed (via a captured browser
        // session against the real API) to use the lowercase literal "application" in the
        // CreateQueryRequest.Level field, unlike the Title-case "Application"/"Tenant"/"Project"
        // values used on the read side (query.Level, tree node Title). Do not "fix" this back to
        // Query_Level_Application without re-verifying against the live API.
        private const string _applicationWriteLevel = "application";

        /// <summary>
        /// Overrides a query at an Application level. Application-level overrides are written
        /// through an ordinary Project session (there is no Application-scoped session) — the
        /// server resolves the owning Application from the project itself.
        /// </summary>
        /// <param name="projectId">A project belonging to the Application to override the query for.</param>
        /// <param name="language">Query language (case insensitive)</param>
        /// <param name="queryName">Query Name (case insensitive)</param>
        /// <param name="querySource">Query Source</param>
        /// <param name="scanId">The ID of the scan to create a session</param>
        /// <exception cref="Exception"></exception>
        /// <exception cref="NotSupportedException">The project belongs to more than one Application — which Application the override would apply to is unverified.</exception>
        public void OverrideApplicationQuerySource(Guid projectId, string language, string queryName, string querySource, Guid? scanId = null)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentNullException(nameof(projectId));

            if (string.IsNullOrWhiteSpace(language))
                throw new ArgumentException(nameof(language));

            if (string.IsNullOrWhiteSpace(queryName))
                throw new ArgumentException(nameof(queryName));

            if (string.IsNullOrWhiteSpace(querySource))
                throw new ArgumentException(nameof(querySource));

            if (_client.GetProjectApplications(projectId).Count() > 1)
                throw new NotSupportedException(
                    $"Project {projectId} belongs to more than one Application. Overriding a query at the Application " +
                    "level for a project with multiple Applications is not supported — the server's resolution behavior in that case is unverified.");

            var session = getQueryEditorSessionKey(Query_Level_Project, language, projectId, scanId);

            try
            {
                overrideApplicationQuerySourceInSession(session, language, queryName, querySource);
            }
            finally { endQueryEditorSession(session); }
        }

        private void overrideApplicationQuerySourceInSession(Guid session, string language, string queryName, string querySource)
        {
            var tree = QueryEditor.GetQueriesAsync(session, includeMetadata: true).Result;
            overrideApplicationQuerySourceInSession(tree, session, language, queryName, querySource);
        }

        // Tree-accepting overload used by the batch method below, which fetches the tree once for the
        // whole batch (see CreateOrOverrideApplicationQuerySources) instead of once per item.
        private void overrideApplicationQuerySourceInSession(IEnumerable<QueriesTree> tree, Guid session, string language, string queryName, string querySource)
        {
            var query = findQueryInTree(tree, session, language, queryName);

            if (query == null)
                throw new Exception($"No query found for language {language} with the name {queryName}");

            if (query.Level == Query_Level_Application)
            {
                if (query.Source != querySource)
                    updateQuerySourceByEditorQuery(session, query.Id, querySource);
            }
            else
            {
                createQuery(session, query, _applicationWriteLevel, querySource);
            }
        }

        /// <summary>
        /// Creates or overrides several Application-level queries through a single project's session,
        /// instead of opening one read/write session pair per query — the project must belong to
        /// exactly one Application (see <see cref="OverrideApplicationQuerySource"/>).
        /// </summary>
        public IEnumerable<QueryBatchResult> CreateOrOverrideApplicationQuerySources(Guid representativeProjectId, IEnumerable<ProjectQueryUpsert> queries, Guid? scanId = null)
        {
            if (representativeProjectId == Guid.Empty)
                throw new ArgumentNullException(nameof(representativeProjectId));

            if (_client.GetProjectApplications(representativeProjectId).Count() > 1)
                throw new NotSupportedException(
                    $"Project {representativeProjectId} belongs to more than one Application. Overriding queries at the Application " +
                    "level for a project with multiple Applications is not supported — the server's resolution behavior in that case is unverified.");

            var results = new List<QueryBatchResult>();

            var session = getQueryEditorSessionKey(Query_Level_Project, null, representativeProjectId, scanId);
            try
            {
                // Fetched once for the whole batch and reused per item — see findQueryInTree.
                ICollection<QueriesTree> tree;
                try
                {
                    tree = QueryEditor.GetQueriesAsync(session, includeMetadata: true).Result;
                }
                catch (Exception ex)
                {
                    foreach (var item in queries)
                        results.Add(new QueryBatchResult { Language = item.Language, QueryName = item.QueryName, Success = false, ErrorMessage = ex.Message });
                    return results;
                }

                foreach (var item in queries)
                {
                    try
                    {
                        overrideApplicationQuerySourceInSession(tree, session, item.Language, item.QueryName, item.QuerySource);
                        results.Add(new QueryBatchResult { Language = item.Language, QueryName = item.QueryName, Success = true });
                    }
                    catch (Exception ex)
                    {
                        results.Add(new QueryBatchResult { Language = item.Language, QueryName = item.QueryName, Success = false, ErrorMessage = ex.Message });
                    }
                }
            }
            finally { endQueryEditorSession(session); }

            return results;
        }

        /// <summary>
        /// Overrides a query at a tenant level
        /// </summary>
        /// <param name="language">Query language (case insensitive)</param>
        /// <param name="queryName">Query Name (case insensitive)</param>
        /// <param name="querySource">Query Source</param>
        /// <returns>Returns the query editor key</returns>
        /// <exception cref="Exception"></exception>
        public void OverrideTenantQuerySource(string language, string queryName, string querySource)
        {
            if (string.IsNullOrWhiteSpace(language))
                throw new ArgumentException(nameof(language));

            if (string.IsNullOrWhiteSpace(queryName))
                throw new ArgumentException(nameof(queryName));

            if (string.IsNullOrWhiteSpace(querySource))
                throw new ArgumentException(nameof(querySource));

            var session = getQueryEditorSessionKey(Query_Level_Tenant, language);

            try
            {
                var query = getQueryByLanguageAndName(session, language, queryName);

                if (query == null)
                    throw new Exception($"No query found for language {language} with the name {queryName}");

                // If there is an existing query at the tenant level already, call the method to update the source code
                // If not, create the new query
                if (query.Level == Query_Level_Tenant)
                {
                    // Do not update the source code if there is no differences. API will throw an error "error modifying query environment"
                    if (query.Source != querySource)
                        updateQuerySourceByEditorQuery(session, query.Id, querySource);
                }
                else
                {
                    // For some reason, in the current API version (and for tenant queries), you cannot send the query source in the creation body
                    // You need to create the query and update the source code after
                    CreateQueryRequest createBody = new CreateQueryRequest()
                    {
                        Name = query.Name,
                        Language = query.Metadata.Language,
                        Group = query.Metadata.Group,
                        Severity = query.Metadata.Severity,
                        Executable = query.Metadata.Executable
                    };

                    var queryId = requestQueryCreation(session, createBody);

                    updateQuerySourceByEditorQuery(session, queryId, querySource);
                }
            }
            finally { endQueryEditorSession(session); }
        }

        /// <summary>
        /// Create a query at a tenant level
        /// </summary>
        /// <param name="language">Query language</param>
        /// <param name="queryName">Query Name</param>
        /// <param name="group">Query Group</param>
        /// <param name="severity">Query Severity</param>
        /// <param name="source">Query Source</param>
        /// <param name="isExecutable">Is the query executable</param>
        /// <returns>Returns the query editor key</returns>
        /// <exception cref="Exception"></exception>
        public void CreateTenantQuery(string language, string queryName, string group, string severity, string source, bool isExecutable)
        {
            if (string.IsNullOrWhiteSpace(language))
                throw new ArgumentException(nameof(language));

            if (string.IsNullOrWhiteSpace(queryName))
                throw new ArgumentException(nameof(queryName));

            if (string.IsNullOrWhiteSpace(group))
                throw new ArgumentException(nameof(group));

            if (string.IsNullOrWhiteSpace(severity))
                throw new ArgumentException(nameof(severity));

            if (string.IsNullOrWhiteSpace(source))
                throw new ArgumentException(nameof(source));

            var session = getQueryEditorSessionKey(Query_Level_Tenant, language);

            try
            {
                CreateQueryRequest createBody = new CreateQueryRequest()
                {
                    Name = queryName,
                    Language = language,
                    Group = group,
                    Severity = severity,
                    Executable = isExecutable
                };

                var queryId = requestQueryCreation(session, createBody);

                updateQuerySourceByEditorQuery(session, queryId, source);
            }
            finally { endQueryEditorSession(session); }
        }

        #region Batched Query Editor Operations

        // QueryBatchResult / TenantQueryUpsert / ProjectQueryUpsert stay defined on ASTClient itself
        // (see ASTClient.cs) rather than moving here — they're pure DTOs referenced throughout the rest
        // of the solution as ASTClient.QueryBatchResult etc. (e.g. CxOneInstance.cs, CxOneDevOps.cs),
        // and moving them would have broken every one of those call sites for no benefit. They resolve
        // unqualified here via the `using static Checkmarx.API.AST.ASTClient;` at the top of this file.

        /// <summary>
        /// Reads the source of several Tenant-level queries, opening one session per distinct
        /// language instead of one session per query.
        /// </summary>
        public IEnumerable<QueryBatchResult> GetTenantQuerySources(IEnumerable<(string Language, string QueryName)> queries)
        {
            var results = new List<QueryBatchResult>();

            foreach (var languageGroup in queries.GroupBy(q => q.Language))
            {
                var session = getQueryEditorSessionKey(Query_Level_Tenant, languageGroup.Key);
                try
                {
                    // Fetched once per session and reused for every query in this language group —
                    // see findQueryInTree — rather than once per query, which is the dominant cost
                    // once a batch covers every Cx-level query in the tenant, not just a handful of
                    // overrides.
                    ICollection<QueriesTree> tree;
                    try
                    {
                        tree = QueryEditor.GetQueriesAsync(session, includeMetadata: true).Result;
                    }
                    catch (Exception ex)
                    {
                        foreach (var (language, queryName) in languageGroup)
                            results.Add(new QueryBatchResult { Language = language, QueryName = queryName, Success = false, ErrorMessage = ex.Message });
                        continue;
                    }

                    foreach (var (language, queryName) in languageGroup)
                    {
                        try
                        {
                            var query = findQueryInTree(tree, session, language, queryName);
                            if (query == null)
                                throw new Exception($"No query found for language {language} with the name {queryName}");

                            results.Add(new QueryBatchResult { Language = language, QueryName = queryName, Success = true, Source = query.Source });
                        }
                        catch (Exception ex)
                        {
                            results.Add(new QueryBatchResult { Language = language, QueryName = queryName, Success = false, ErrorMessage = ex.Message });
                        }
                    }
                }
                finally { endQueryEditorSession(session); }
            }

            return results;
        }

        /// <summary>
        /// Reads the source of several Project-level queries for a single project/scan, opening
        /// exactly one session for the whole call instead of one session per query.
        /// </summary>
        public IEnumerable<QueryBatchResult> GetProjectQuerySources(Guid projectId, IEnumerable<(string Language, string QueryName)> queries, Guid? scanId = null)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentNullException(nameof(projectId));

            var results = new List<QueryBatchResult>();

            var session = getQueryEditorSessionKey(Query_Level_Project, null, projectId, scanId);
            try
            {
                // Fetched once for the whole batch and reused per query — see findQueryInTree.
                ICollection<QueriesTree> tree;
                try
                {
                    tree = QueryEditor.GetQueriesAsync(session, includeMetadata: true).Result;
                }
                catch (Exception ex)
                {
                    foreach (var (language, queryName) in queries)
                        results.Add(new QueryBatchResult { Language = language, QueryName = queryName, Success = false, ErrorMessage = ex.Message });
                    return results;
                }

                foreach (var (language, queryName) in queries)
                {
                    try
                    {
                        var query = findQueryInTree(tree, session, language, queryName);
                        if (query == null)
                            throw new Exception($"No query found for language {language} with the name {queryName}");

                        results.Add(new QueryBatchResult { Language = language, QueryName = queryName, Success = true, Source = query.Source });
                    }
                    catch (Exception ex)
                    {
                        results.Add(new QueryBatchResult { Language = language, QueryName = queryName, Success = false, ErrorMessage = ex.Message });
                    }
                }
            }
            finally { endQueryEditorSession(session); }

            return results;
        }

        /// <summary>
        /// Creates or overrides several Tenant-level queries, opening one session per distinct
        /// language instead of one (or two, via a separate existence probe) session per query.
        /// </summary>
        public IEnumerable<QueryBatchResult> CreateOrOverrideTenantQuerySources(IEnumerable<TenantQueryUpsert> queries)
        {
            var results = new List<QueryBatchResult>();

            foreach (var languageGroup in queries.GroupBy(q => q.Language))
            {
                var session = getQueryEditorSessionKey(Query_Level_Tenant, languageGroup.Key);
                try
                {
                    // Fetched once per session and reused per item — see findQueryInTree.
                    ICollection<QueriesTree> tree;
                    try
                    {
                        tree = QueryEditor.GetQueriesAsync(session, includeMetadata: true).Result;
                    }
                    catch (Exception ex)
                    {
                        foreach (var item in languageGroup)
                            results.Add(new QueryBatchResult { Language = item.Language, QueryName = item.QueryName, Success = false, ErrorMessage = ex.Message });
                        continue;
                    }

                    foreach (var item in languageGroup)
                    {
                        try
                        {
                            upsertTenantQuerySourceInSession(tree, session, item);
                            results.Add(new QueryBatchResult { Language = item.Language, QueryName = item.QueryName, Success = true });
                        }
                        catch (Exception ex)
                        {
                            results.Add(new QueryBatchResult { Language = item.Language, QueryName = item.QueryName, Success = false, ErrorMessage = ex.Message });
                        }
                    }
                }
                finally { endQueryEditorSession(session); }
            }

            return results;
        }

        /// <summary>
        /// Creates or overrides several Project-level queries for a single project/scan, opening
        /// exactly one session for the whole call instead of one session per query.
        /// </summary>
        public IEnumerable<QueryBatchResult> CreateOrOverrideProjectQuerySources(Guid projectId, IEnumerable<ProjectQueryUpsert> queries, Guid? scanId = null)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentNullException(nameof(projectId));

            var results = new List<QueryBatchResult>();

            var session = getQueryEditorSessionKey(Query_Level_Project, null, projectId, scanId);
            try
            {
                // Fetched once for the whole batch and reused per item — see findQueryInTree.
                ICollection<QueriesTree> tree;
                try
                {
                    tree = QueryEditor.GetQueriesAsync(session, includeMetadata: true).Result;
                }
                catch (Exception ex)
                {
                    foreach (var item in queries)
                        results.Add(new QueryBatchResult { Language = item.Language, QueryName = item.QueryName, Success = false, ErrorMessage = ex.Message });
                    return results;
                }

                foreach (var item in queries)
                {
                    try
                    {
                        var query = findQueryInTree(tree, session, item.Language, item.QueryName);
                        if (query == null)
                            throw new Exception($"No query found for language {item.Language} with the name {item.QueryName} for project {projectId}");

                        if (query.Level == Query_Level_Project)
                        {
                            if (query.Source != item.QuerySource)
                                updateQuerySourceByEditorQuery(session, query.Id, item.QuerySource);
                        }
                        else
                        {
                            createQuery(session, query, Query_Level_Project, item.QuerySource);
                        }

                        results.Add(new QueryBatchResult { Language = item.Language, QueryName = item.QueryName, Success = true });
                    }
                    catch (Exception ex)
                    {
                        results.Add(new QueryBatchResult { Language = item.Language, QueryName = item.QueryName, Success = false, ErrorMessage = ex.Message });
                    }
                }
            }
            finally { endQueryEditorSession(session); }

            return results;
        }

        // Takes an already-fetched tree — the batch method below fetches it once per session and
        // reuses it across every item, instead of once per item. See findQueryInTree.
        private void upsertTenantQuerySourceInSession(IEnumerable<QueriesTree> tree, Guid session, TenantQueryUpsert item)
        {
            var query = findQueryInTree(tree, session, item.Language, item.QueryName);

            if (query == null)
            {
                if (string.IsNullOrWhiteSpace(item.Group) || string.IsNullOrWhiteSpace(item.Severity) || !item.IsExecutable.HasValue)
                    throw new ArgumentNullException(nameof(item.Group), $"Group, Severity and IsExecutable are required to create the new tenant query {item.Language} {item.QueryName}.");

                CreateQueryRequest createBody = new CreateQueryRequest()
                {
                    Name = item.QueryName,
                    Language = item.Language,
                    Group = item.Group,
                    Severity = item.Severity,
                    Executable = item.IsExecutable.Value
                };

                var queryId = requestQueryCreation(session, createBody);
                updateQuerySourceByEditorQuery(session, queryId, item.QuerySource);
            }
            else if (query.Level == Query_Level_Tenant)
            {
                if (query.Source != item.QuerySource)
                    updateQuerySourceByEditorQuery(session, query.Id, item.QuerySource);
            }
            else
            {
                // Found at Cx level, not yet overridden at Tenant level. The new Tenant-level override
                // must be created with the CALLER's Group/Severity/IsExecutable, not this query's own
                // (target-side) Cx metadata: the two tenants can report different Group/Severity for
                // the "same" base query (e.g. differing SAST engine versions), and identity-based
                // comparisons elsewhere key off the source tenant's Group. Creating the override with
                // the target's own Group instead of the source's silently produces a Tenant-level query
                // that never matches that identity again, so it gets endlessly re-detected as missing.
                if (string.IsNullOrWhiteSpace(item.Group) || string.IsNullOrWhiteSpace(item.Severity) || !item.IsExecutable.HasValue)
                    throw new ArgumentNullException(nameof(item.Group), $"Group, Severity and IsExecutable are required to override the tenant query {item.Language} {item.QueryName}.");

                // For some reason, in the current API version (and for tenant queries), you cannot send the query source in the creation body
                // You need to create the query and update the source code after
                CreateQueryRequest createBody = new CreateQueryRequest()
                {
                    Name = query.Name,
                    Language = item.Language,
                    Group = item.Group,
                    Severity = item.Severity,
                    Executable = item.IsExecutable.Value
                };

                var queryId = requestQueryCreation(session, createBody);
                updateQuerySourceByEditorQuery(session, queryId, item.QuerySource);
            }
        }

        #endregion

        /// <summary>
        /// Deletes a query at a Project level
        /// </summary>
        /// <param name="projectId">The ID of the project to delete the query for</param>
        /// <param name="language">Query language (case insensitive)</param>
        /// <param name="queryName">Query Name (case insensitive)</param>
        /// <param name="withQueryDescription">Only deletes query, if the query source contains the description (case insensitive)</param>
        /// <param name="scanId">The ID of the scan to create a session</param>
        /// <exception cref="Exception"></exception>
        public bool DeleteProjectQuery(Guid projectId, string language, string queryName, string withQueryDescription = null, Guid? scanId = null)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentNullException(nameof(projectId));

            if (string.IsNullOrWhiteSpace(language))
                throw new ArgumentException(nameof(language));

            if (string.IsNullOrWhiteSpace(queryName))
                throw new ArgumentException(nameof(queryName));

            var session = getQueryEditorSessionKey(Query_Level_Project, language, projectId, scanId);

            try
            {
                var query = getQueryByLanguageAndName(session, language, queryName);

                if (query == null)
                    throw new Exception($"No query found for language {language} with the name {queryName}");

                if (query.Level != Query_Level_Project)
                    throw new Exception($"The detected query is at {query.Level} level, and not at {Query_Level_Project} level.");

                // In cases were we just want to delete queries with a certain description added in the source
                if (!string.IsNullOrWhiteSpace(withQueryDescription))
                {
                    if (!query.Source.ToLower().Contains(withQueryDescription.ToLower()))
                        throw new Exception($"The detected query does not contain the description provided.");
                }

                return deleteQueryWithSessionId(session, query.Id);
            }
            finally { endQueryEditorSession(session); }
        }

        /// <summary>
        /// Deletes a query at an Application level, through an ordinary Project session (there is
        /// no Application-scoped session — the server resolves the owning Application from the project).
        /// </summary>
        /// <param name="projectId">A project belonging to the Application to delete the query for.</param>
        /// <param name="language">Query language (case insensitive)</param>
        /// <param name="queryName">Query Name (case insensitive)</param>
        /// <param name="withQueryDescription">Only deletes query, if the query source contains the description (case insensitive)</param>
        /// <param name="scanId">The ID of the scan to create a session</param>
        /// <exception cref="Exception"></exception>
        /// <exception cref="NotSupportedException">The project belongs to more than one Application — which Application the query would be deleted from is unverified.</exception>
        public bool DeleteApplicationQuery(Guid projectId, string language, string queryName, string withQueryDescription = null, Guid? scanId = null)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentNullException(nameof(projectId));

            if (string.IsNullOrWhiteSpace(language))
                throw new ArgumentException(nameof(language));

            if (string.IsNullOrWhiteSpace(queryName))
                throw new ArgumentException(nameof(queryName));

            if (_client.GetProjectApplications(projectId).Count() > 1)
                throw new NotSupportedException(
                    $"Project {projectId} belongs to more than one Application. Deleting a query at the Application " +
                    "level for a project with multiple Applications is not supported — the server's resolution behavior in that case is unverified.");

            var session = getQueryEditorSessionKey(Query_Level_Project, language, projectId, scanId);

            try
            {
                var query = getQueryByLanguageAndName(session, language, queryName);

                if (query == null)
                    throw new Exception($"No query found for language {language} with the name {queryName}");

                if (query.Level != Query_Level_Application)
                    throw new Exception($"The detected query is at {query.Level} level, and not at {Query_Level_Application} level.");

                // In cases were we just want to delete queries with a certain description added in the source
                if (!string.IsNullOrWhiteSpace(withQueryDescription))
                {
                    if (!query.Source.ToLower().Contains(withQueryDescription.ToLower()))
                        throw new Exception($"The detected query does not contain the description provided.");
                }

                return deleteQueryWithSessionId(session, query.Id);
            }
            finally { endQueryEditorSession(session); }
        }

        /// <summary>
        /// Deletes a query at a Tenant level
        /// </summary>
        /// <param name="language">Query language (case insensitive)</param>
        /// <param name="queryName">Query Name (case insensitive)</param>
        /// <param name="withQueryDescription">Only deletes query, if the query source contains the description (case insensitive)</param>
        /// <exception cref="Exception"></exception>
        public bool DeleteTenantQuery(string language, string queryName, string withQueryDescription = null)
        {
            if (string.IsNullOrWhiteSpace(language))
                throw new ArgumentException(nameof(language));

            if (string.IsNullOrWhiteSpace(queryName))
                throw new ArgumentException(nameof(queryName));

            var session = getQueryEditorSessionKey(Query_Level_Tenant, language);

            try
            {
                var query = getQueryByLanguageAndName(session, language, queryName);

                if (query == null)
                    throw new Exception($"No query found for language {language} with the name {queryName}");

                if (query.Level != Query_Level_Tenant)
                    throw new Exception($"The detected query is at {query.Level} level, and not at {Query_Level_Tenant} level.");

                // In cases were we just want to delete queries with a certain description added in the source
                if (!string.IsNullOrWhiteSpace(withQueryDescription))
                {
                    if (!query.Source.ToLower().Contains(withQueryDescription.ToLower()))
                        throw new Exception($"The detected query does not contain the description provided.");
                }

                return deleteQueryWithSessionId(session, query.Id);
            }
            finally { endQueryEditorSession(session); }
        }

        /// <summary>
        /// Deletes a query at a Project or Tenant level through the query editor key
        /// </summary>
        /// <param name="queryKey">Query Editor Key</param>
        /// <param name="language">Query language (case insensitive)</param>
        /// <param name="projectId">The ID of the project to create a session. Mandatory if it is a project level query</param>
        /// <param name="scanId">The ID of the scan to create a session</param>
        /// <exception cref="Exception"></exception>
        public bool DeleteQueryByKey(string queryKey, string language, Guid? projectId = null, Guid? scanId = null)
        {
            if (string.IsNullOrWhiteSpace(queryKey))
                throw new ArgumentException(nameof(queryKey));

            if (string.IsNullOrWhiteSpace(language))
                throw new ArgumentException(nameof(language));

            string level = Query_Level_Project;
            if (!projectId.HasValue)
                level = Query_Level_Tenant;

            var session = getQueryEditorSessionKey(level, language, projectId, scanId);

            try
            {
                return deleteQueryWithSessionId(session, queryKey);
            }
            finally { endQueryEditorSession(session); }
        }

        /// <summary>
        /// Query details by language and name
        /// </summary>
        /// <param name="language">Query language (case insensitive)</param>
        /// <param name="queryName">Query Name (case insensitive)</param>
        /// <param name="level">The query level (Cx, Tenant or Project)</param>
        /// <param name="projectId">The ID of the project to fetch the query for. Mandatory if the level is Project</param>
        /// <param name="scanId">The ID of the scan to create a session</param>
        /// <returns>Returns the query editor key</returns>
        /// <exception cref="Exception"></exception>
        public QueryResponse GetQueryByLanguageAndName(string language, string queryName, string level, Guid? projectId = null, Guid? scanId = null)
        {
            if (string.IsNullOrWhiteSpace(language))
                throw new ArgumentNullException(nameof(language));

            if (string.IsNullOrWhiteSpace(queryName))
                throw new ArgumentNullException(nameof(queryName));

            if (string.IsNullOrWhiteSpace(level))
                throw new ArgumentNullException(nameof(level));

            if (level == Query_Level_Project && !projectId.HasValue)
                throw new Exception($"In order to fetch information of query level \"{Query_Level_Project}\", you must provide a project id.");

            var session = getQueryEditorSessionKey(level, language, projectId, scanId);

            try
            {
                return getQueryByLanguageAndName(session, language, queryName);
            }
            finally { endQueryEditorSession(session); }
        }

        /// <summary>
        /// Scan Query Nodes
        /// </summary>
        /// <param name="projectId">Project Id</param>
        /// <param name="scanId">Scan Id</param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        public IEnumerable<QueriesTree> GetProjectScanQueryNodes(Guid projectId, Guid scanId)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentNullException(nameof(projectId));

            if (scanId == Guid.Empty)
                throw new ArgumentNullException(nameof(scanId));

            var session = getQueryEditorSessionKey(Query_Level_Project, null, projectId, scanId);

            try
            {
                return QueryEditor.GetQueriesAsync(session, includeMetadata: true).Result;
            }
            finally { endQueryEditorSession(session); }
        }

        /// <summary>
        /// Discovers Application-level query overrides visible through a given project's query
        /// editor session (i.e. through an Application the project belongs to), by walking the
        /// live session tree instead of the plain /queries listing endpoint — confirmed unreliable
        /// for Application-level entries (silently missing a recently created override that the
        /// query editor UI and this same session tree show immediately).
        ///
        /// Unlike the plain listing (which collapses each query to a single "effective" level, so a
        /// project's own Project-level override can hide the Application-level one for that same
        /// project), the session tree exposes Cx/Tenant/Application/Project as sibling branches per
        /// query — so there is no masking risk here: any query under the "Application" branch is
        /// genuinely an Application-level override, regardless of what else that project overrides.
        ///
        /// One session covers every language in one call (no language filter), so this costs exactly
        /// one session for the whole project, not one per language.
        ///
        /// The server also accepts a "level" query parameter to prune the response down to just the
        /// Application branch — but that parameter is NOT used here: confirmed (via a live test) that
        /// it reliably triggers a server-side 500 ("error getting queries", code 796) on projects that
        /// belong to more than one Application, while the identical unfiltered call succeeds instantly
        /// on the same project/session. So we always fetch the full tree (Cx/Tenant/Application/Project)
        /// and pick out the Application branch client-side instead.
        ///
        /// Returns the full session query-editor detail (<see cref="QueryResponse"/>,
        /// including Source) rather than the lighter <see cref="Services.SASTQueriesAudit.Queries"/> used
        /// by the plain listing endpoint — callers that need the source of an Application-level override
        /// (e.g. the tenant migration, to compare/copy it) would otherwise have to open a second session
        /// via GetQuerySource, which carries a real masking risk: if the representative project used for
        /// discovery also happens to carry its own Project-level override of the same query, a fresh
        /// language+name lookup would silently resolve to that Project-level source instead (Project
        /// outranks Application in getQueryByLanguageAndName's priority walk). Reusing the detail already
        /// fetched here avoids both the extra session and that risk. This depends entirely on the
        /// GetQueryAsync call below passing includeSource: true — confirmed live: leaving it false
        /// returns a QueryResponse with every other field populated but Source silently null, which
        /// surfaces downstream as an opaque "Value cannot be null (Parameter 'source')" at write time,
        /// nowhere near this method.
        /// </summary>
        public IEnumerable<QueryResponse> GetApplicationLevelQueriesFromSession(Guid projectId, Guid? scanId = null)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentNullException(nameof(projectId));

            var session = getQueryEditorSessionKey(Query_Level_Project, null, projectId, scanId);

            try
            {
                var tree = QueryEditor.GetQueriesAsync(session, includeMetadata: true).Result;
                var result = new List<QueryResponse>();

                foreach (var languageNode in tree ?? Enumerable.Empty<QueriesTree>())
                {
                    var applicationNode = languageNode.Children?.SingleOrDefault(x => string.Equals(x.Title, Query_Level_Application, StringComparison.OrdinalIgnoreCase));
                    if (applicationNode == null)
                        continue;

                    foreach (var leaf in collectLeaves(applicationNode))
                    {
                        var detail = QueryEditor.GetQueryAsync(session, leaf.Key, includeMetadata: true, includeSource: true).Result;
                        if (detail == null)
                            continue;

                        // Normalize Level/Language the same defensive way the old Queries-mapping did —
                        // the query's own reported level/language can be inconsistent with the tree
                        // branch it was actually found under.
                        detail.Level = Query_Level_Application;
                        if (detail.Metadata != null)
                            detail.Metadata.Language = languageNode.Title;

                        result.Add(detail);
                    }
                }

                return result;
            }
            finally { endQueryEditorSession(session); }
        }

        private static IEnumerable<QueriesTree> collectLeaves(QueriesTree node)
        {
            if (node.Children == null || !node.Children.Any())
            {
                if (node.IsLeaf)
                    yield return node;

                yield break;
            }

            foreach (var child in node.Children)
                foreach (var leaf in collectLeaves(child))
                    yield return leaf;
        }

        private string createQuery(Guid session, QueryResponse query, string level, string source)
        {
            if (query == null)
                throw new ArgumentNullException(nameof(query));

            if (string.IsNullOrWhiteSpace(level))
                throw new ArgumentNullException(nameof(level));

            if (string.IsNullOrWhiteSpace(source))
                throw new ArgumentNullException(nameof(source));

            if (level != Query_Level_Tenant && level != Query_Level_Project && level != _applicationWriteLevel)
                throw new Exception($"You can only create a query at {Query_Level_Tenant}, {Query_Level_Project} or Application level.");

            return createQueryByEditorQuery(session, query.Id, query.Name, query.Path, query.Metadata.Cwe, query.Metadata.Language, query.Metadata.Group, query.Metadata.Severity, query.Metadata.Executable, query.Metadata.Description, query.Metadata.SastId, query.Metadata.Presets?.ToList(), level, source);
        }

        private Guid getProjectScanIdForQueryEditorSession(Guid projectId)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentNullException(nameof(projectId));

            var lastScan = _client.GetLastScan(projectId, completed: false);

            if (lastScan == null)
                throw new InvalidOperationException($"No scan found for project id {projectId}");

            return lastScan.Id;
        }

        #region Session lifecycle

        private Guid getQueryEditorSessionKey(string level, string language = null, Guid? projectId = null, Guid? scanId = null)
        {
            if (level != Query_Level_Tenant && level != Query_Level_Project)
                throw new Exception($"You can only create a query editor session for {Query_Level_Tenant} and {Query_Level_Project} levels.");

            var gate = querySessionGate;

            // Block until a session slot is available or we time out. This is the primary guard
            // against exceeding the tenant-wide session limit when called from parallel code.
            if (!gate.Wait(_querySessionAcquireTimeout))
                throw new TimeoutException(
                    $"Could not acquire a query editor session slot within {_querySessionAcquireTimeout.TotalMinutes} minutes. " +
                    "The tenant may have reached its maximum concurrent session limit.");

            bool sessionCreated = false;
            try
            {
                Guid id;
                if (level == Query_Level_Tenant)
                {
                    if (string.IsNullOrWhiteSpace(language))
                        throw new ArgumentNullException(nameof(language));

                    id = createQueryEditorSessionWithRetry(() => createQueryEditorNewSessionId(language));
                }
                else
                {
                    if (!projectId.HasValue || projectId == Guid.Empty)
                        throw new ArgumentNullException(nameof(projectId));

                    if (!scanId.HasValue)
                        scanId = getProjectScanIdForQueryEditorSession(projectId.Value);

                    id = createQueryEditorSessionWithRetry(() => createQueryEditorNewSessionId(projectId.Value, scanId.Value));
                }

                // Session exists on the server — ownership transfers to endQueryEditorSession.
                sessionCreated = true;
                return id;
            }
            catch
            {
                // Session was never created — release the slot now; endQueryEditorSession won't be called.
                if (!sessionCreated)
                    gate.Release();
                throw;
            }
        }

        // Retries session creation to ride out contention from other users/processes sharing the
        // tenant's session limit, since the API no longer exposes a way to check availability upfront.
        // Every failed attempt is logged with full diagnostics, since nobody currently knows the exact
        // shape of the server's "no slots available" error.
        private Guid createQueryEditorSessionWithRetry(Func<Guid> createSession)
        {
            Exception lastError = null;
            for (int attempt = 1; attempt <= _querySessionCreateMaxAttempts; attempt++)
            {
                try
                {
                    return createSession();
                }
                catch (Exception ex)
                {
                    lastError = ex;

                    // .Result wraps a faulted task's exception in an AggregateException — unwrap it
                    // to actually see the ApiException and its status code, instead of always falling
                    // through to the generic "unknown failure" branch.
                    var apiEx = unwrapApiException(ex);
                    string details = apiEx != null
                        ? $"StatusCode={apiEx.StatusCode}, Response={apiEx.Response}"
                        : ex.ToString();

                    System.Diagnostics.Trace.TraceWarning(
                        $"[QueryEditor] Session creation attempt {attempt}/{_querySessionCreateMaxAttempts} failed: {details}");

                    // A 4xx response is a permanent, client-side rejection (e.g. a malformed request
                    // for this specific project) — retrying it verbatim will never succeed, so don't
                    // burn the backoff delay on further attempts.
                    if (apiEx != null && apiEx.StatusCode >= 400 && apiEx.StatusCode < 500)
                        throw new InvalidOperationException(
                            $"Could not create a query editor session: the server rejected the request (status {apiEx.StatusCode}).",
                            ex);

                    if (attempt < _querySessionCreateMaxAttempts)
                        System.Threading.Thread.Sleep(_querySessionCreateRetryDelay);
                }
            }

            throw new InvalidOperationException(
                $"Could not create a query editor session after {_querySessionCreateMaxAttempts} attempts. ",
                lastError);
        }

        private static Exceptions.ApiException unwrapApiException(Exception ex)
        {
            if (ex is Exceptions.ApiException direct)
                return direct;

            if (ex is AggregateException agg)
                return agg.Flatten().InnerExceptions.OfType<Exceptions.ApiException>().FirstOrDefault();

            return null;
        }

        private Guid createQueryEditorNewSessionId(Guid projectId, Guid scanId)
        {
            if (projectId == Guid.Empty)
                throw new ArgumentNullException(nameof(projectId));

            if (scanId == Guid.Empty)
                throw new ArgumentNullException(nameof(scanId));

            _currentSessionSubject.Value = $"project {projectId}, scan {scanId}";
            var session = QueryEditor.CreateSessionAsync(new SessionRequest() { ProjectId = projectId, ScanId = scanId, Scanner = "sast", Timeout = 120 }).Result;

            return checkSessionStatusAndGetId(session, projectId: projectId);
        }
        private Guid createQueryEditorNewSessionId(string language)
        {
            if (string.IsNullOrWhiteSpace(language))
                throw new ArgumentNullException(nameof(language));

            language = language.Trim().ToLower();

            _currentSessionSubject.Value = $"language {language}";
            var session = QueryEditor.CreateSessionAsync(new SessionRequest() { Filter = language, Scanner = "sast", Timeout = 120 }).Result;

            return checkSessionStatusAndGetId(session, language: language);
        }
        private Guid checkSessionStatusAndGetId(SessionResponse session, Guid? projectId = null, string language = null)
        {
            var deadline = DateTime.UtcNow + _sessionProvisioningTimeout;

            bool completed = false;
            Guid? id = null;
            while (!completed)
            {
                System.Threading.Thread.Sleep(TimeSpan.FromSeconds(5));

                if (DateTime.UtcNow > deadline)
                {
                    // The session's provisioning job never reached a terminal status within the
                    // allotted time — see _sessionProvisioningTimeout. Abandon it the same way as a
                    // Failed/Canceled status below, rather than looping forever.
                    abandonSession(session.Id);

                    string timeoutMessage = $"Timed out after {_sessionProvisioningTimeout.TotalMinutes:0} minute(s) waiting for a query editor session to finish provisioning";
                    if (projectId.HasValue)
                        timeoutMessage += $" for project {projectId}";
                    else if (!string.IsNullOrWhiteSpace(language))
                        timeoutMessage += $" for language {language}";

                    throw new TimeoutException(timeoutMessage + ".");
                }

                RequestSessionStatus status;
                try
                {
                    status = QueryEditor.CheckRequestSessionStatusAsync(session.Id, session.Data.RequestID.Value).Result;
                }
                catch
                {
                    // session.Id was already allocated server-side by the CreateSessionAsync call that
                    // produced `session` — bailing out here without deleting it leaks a real, counted
                    // session slot, same as the non-Finished branch below.
                    abandonSession(session.Id);
                    throw;
                }

                if (status.Completed)
                {
                    completed = true;
                    if (status.Status == RequestStatusStatus.Finished)
                        id = session.Id;
                    else
                    {
                        // The session exists server-side (it has an Id) but this client is never going
                        // to use it — nothing else in the creation/retry path above ever calls
                        // DeleteSessionAsync for a session that doesn't make it back to
                        // getQueryEditorSessionKey's caller, so without this it leaks indefinitely. An
                        // unlucky project/scan (e.g. the already-known "shared by several Applications"
                        // case, which fails this same way) previously abandoned one real session per
                        // occurrence — invisible locally, since querySessionGate still gets released,
                        // but very visible once enough pile up and the tenant starts rejecting brand
                        // new sessions with error 776, "the maximum number of sessions has been
                        // reached".
                        abandonSession(session.Id);

                        string errorMessage = $"Error creating query session with status \"{status.Status}\".";
                        if (projectId.HasValue)
                            errorMessage = $"Error creating query session for project {projectId} with status \"{status.Status}\".";
                        else if (!string.IsNullOrWhiteSpace(language))
                            errorMessage = $"Error creating session for language {language} with status \"{status.Status}\".";

                        throw new Exception(errorMessage);
                    }
                }
            }

            if (id == null)
            {
                string errorMessage = $"Unknown error creating session";
                if (projectId.HasValue)
                    errorMessage = $"Unknown error creating session for project {projectId}";
                else if (!string.IsNullOrWhiteSpace(language))
                    errorMessage = $"Unknown error creating session for language {language}";

                throw new Exception(errorMessage);
            }

            return id.Value;
        }

        // Best-effort cleanup for a session this client decided not to use (see checkSessionStatusAndGetId)
        // rather than one it finished using (see endQueryEditorSession) — kept separate because callers
        // reach this one without ever holding a "successfully created" session to run the normal
        // try/finally around.
        private void abandonSession(Guid sessionId)
        {
            try
            {
                QueryEditor.DeleteSessionAsync(sessionId).Wait();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[QueryEditor] Failed to delete abandoned session {sessionId}: {ex.Message}");
            }
        }
        private void endQueryEditorSession(Guid session)
        {
            try
            {
                QueryEditor.DeleteSessionAsync(session).Wait();
            }
            catch (Exception ex)
            {
                // Log but do not rethrow — a failed DELETE must never mask the original operation's result.
                // The session will expire on its own via the server-side timeout, but until then it still
                // counts against the tenant's real 5-session cap even though our own semaphore slot below
                // is released right away — worth knowing about when session creation elsewhere starts
                // failing. Trace.TraceWarning has no listener in the actual console app (only in unit
                // tests, via MSTest's own listener) and was confirmed elsewhere in this codebase to
                // silently swallow exactly this kind of failure — Console.WriteLine is what actually
                // reaches the user here, consistent with the retry logging just above.
                Console.WriteLine($"[QueryEditor] Failed to delete session {session}: {ex.Message}");
            }
            finally
            {
                querySessionGate.Release();
            }
        }

        private QueryResponse getQueryByLanguageAndName(Guid session, string language, string queryName)
        {
            var tree = QueryEditor.GetQueriesAsync(session, includeMetadata: true).Result;
            return findQueryInTree(tree, session, language, queryName);
        }

        // Looks up a query by language+name within an already-fetched session tree and applies the
        // Project > Application > Tenant > Cx precedence walk. Split out from the tree-fetching
        // overload above so a caller reading many queries out of the same session (GetTenantQuerySources,
        // GetProjectQuerySources) can fetch the tree once and reuse it, instead of re-fetching the
        // entire session tree per query — negligible for a handful of overrides, but the dominant cost
        // once a batch covers every Cx-level query in the tenant. The final per-query GetQueryAsync
        // call below still happens once per query regardless — the tree only lists queries, it doesn't
        // carry each one's source.
        private QueryResponse findQueryInTree(IEnumerable<QueriesTree> tree, Guid session, string language, string queryName)
        {
            var possibleQueriyToOverride = QueriesTree.FilterTreeByQueryName(tree, queryName)
                                                .SingleOrDefault(x => x.Title.ToLower() == language.ToLower());

            if (possibleQueriyToOverride == null)
                return null;

            // Precedence: Project overrides Application overrides Tenant overrides the Cx default.
            QueriesTree selectedNode = null;
            if (possibleQueriyToOverride.Children.Any(x => string.Equals(x.Title, Query_Level_Project, StringComparison.OrdinalIgnoreCase)))
                selectedNode = possibleQueriyToOverride.Children.Single(x => string.Equals(x.Title, Query_Level_Project, StringComparison.OrdinalIgnoreCase));
            else if (possibleQueriyToOverride.Children.Any(x => string.Equals(x.Title, Query_Level_Application, StringComparison.OrdinalIgnoreCase)))
                selectedNode = possibleQueriyToOverride.Children.Single(x => string.Equals(x.Title, Query_Level_Application, StringComparison.OrdinalIgnoreCase));
            else if (possibleQueriyToOverride.Children.Any(x => string.Equals(x.Title, Query_Level_Tenant, StringComparison.OrdinalIgnoreCase)))
                selectedNode = possibleQueriyToOverride.Children.Single(x => string.Equals(x.Title, Query_Level_Tenant, StringComparison.OrdinalIgnoreCase));
            else if (possibleQueriyToOverride.Children.Any(x => string.Equals(x.Title, Query_Level_Cx, StringComparison.OrdinalIgnoreCase)))
                selectedNode = possibleQueriyToOverride.Children.Single(x => string.Equals(x.Title, Query_Level_Cx, StringComparison.OrdinalIgnoreCase));
            else
                throw new Exception($"Query {queryName} has an unknown Level ");

            // GetLastChildrenByTitle matches case-insensitively, which throws "Sequence contains more
            // than one element" for a real, observed Cx catalog quirk: pairs of queries whose names
            // differ only by case (e.g. Unchecked_Input_For_Loop_Condition vs
            // Unchecked_Input_for_Loop_Condition). We know exactly which one we asked for, so prefer an
            // exact, case-sensitive match when the case-insensitive lookup finds more than one —
            // falling back to the original behavior (and its exception) only if that's still ambiguous.
            var candidateQueries = selectedNode.GetLastChildrenByTitle(queryName);
            var queryDetected = candidateQueries.Count == 1
                ? candidateQueries[0]
                : candidateQueries.First(x => string.Equals(x.Title, queryName, StringComparison.Ordinal));

            return QueryEditor.GetQueryAsync(session, queryDetected.Key, true, true).Result;
        }

        private string createQueryByEditorQuery(Guid session, string editorQueryId, string name, string path, long cwe, string language, string group, string severity, bool executable, long description, long sastId, List<string> presets, string level, string source)
        {
            if (session == Guid.Empty)
                throw new ArgumentNullException(nameof(session));

            CreateQueryRequest createBody = new CreateQueryRequest()
            {
                Name = name,
                Cwe = cwe,
                Language = language,
                Group = group,
                Severity = severity,
                Executable = executable,
                Description = description,

                Id = editorQueryId,
                Level = level,
                Path = path,
                Presets = presets,
                SastId = sastId,

                Source = source
            };

            return requestQueryCreation(session, createBody);
        }

        private string updateQuerySourceByEditorQuery(Guid session, string editorQueryId, string source)
        {
            var createQueryResult = QueryEditor.PutQuerySourceAsync(session, new List<AuditQuery>() { new AuditQuery() { Id = editorQueryId, Source = source } }).Result;

            bool completed = false;
            string id = null;
            while (!completed)
            {
                System.Threading.Thread.Sleep(TimeSpan.FromSeconds(5));

                var status = QueryEditor.CheckRequestStatusAsync(session, createQueryResult.Id).Result;

                if (status.Completed)
                {
                    completed = true;
                    if (status.Status == RequestStatusStatus.Finished)
                        id = status.Value?.Id;
                    else
                        throw new Exception($"Error updating query source with key {editorQueryId}. Message: \"{status.Value.Message}\"");
                }
            }

            if (string.IsNullOrWhiteSpace(id))
                throw new Exception($"Unknown error updating query source with key {editorQueryId}");

            return id;
        }

        private string requestQueryCreation(Guid session, CreateQueryRequest createBody)
        {
            var createQueryResult = QueryEditor.CreateQueryAsync(createBody, session).Result;

            bool completed = false;
            string id = null;
            while (!completed)
            {
                System.Threading.Thread.Sleep(TimeSpan.FromSeconds(5));

                var status = QueryEditor.CheckRequestStatusAsync(session, createQueryResult.Id).Result;

                if (status.Completed)
                {
                    completed = true;
                    if (status.Status == RequestStatusStatus.Finished)
                        id = status.Value?.Id;
                    else
                        throw new Exception($"Error creating query {createBody.Language} {createBody.Name} with status \"{status.Status.ToString()}\". Message: \"{status.Value.Message}\"");
                }
            }

            if (string.IsNullOrWhiteSpace(id))
                throw new Exception($"Unknown error creating query {createBody.Language} {createBody.Name}");

            return id;
        }

        private bool deleteQueryWithSessionId(Guid session, string editorQueryId)
        {
            if (session == Guid.Empty)
                throw new ArgumentNullException(nameof(session));

            if (string.IsNullOrWhiteSpace(editorQueryId))
                throw new ArgumentNullException(nameof(editorQueryId));

            var deleteQueryResult = QueryEditor.DeleteQueryAsync(session, editorQueryId).Result;

            bool completed = false;
            while (!completed)
            {
                System.Threading.Thread.Sleep(TimeSpan.FromSeconds(5));

                var status = QueryEditor.CheckRequestStatusAsync(session, deleteQueryResult.Id).Result;

                if (status.Completed)
                {
                    completed = true;
                    if (status.Status != RequestStatusStatus.Finished)
                        throw new Exception($"Error deleting query with status \"{status.Status.ToString()}\". Message: \"{status.Value.Message}\"");
                }
            }

            return true;
        }

        #endregion
    }
}
