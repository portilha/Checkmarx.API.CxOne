namespace Checkmarx.API.AST.Services.QueryEditor
{
    // Hand-written companion to the NSwag-generated QueryEditor.cs (not touched by regeneration —
    // PrepareRequest is one of the partial method hooks NSwag leaves for exactly this purpose).
    //
    // Every QueryEditor call (session create/delete, get queries, check session status) shares the
    // same QueryEditorClient._retryPolicy, whose "Transient retry" log line has no idea which request
    // it's retrying. This fills QueryEditorClient._currentRequestDescription immediately before each
    // SendAsync so that line can say which endpoint (and, for session-scoped ones, which session id) is
    // actually 500ing — needed to tell a session-limit problem (retries clustered on session creation)
    // apart from a per-query read problem (retries on GetQueriesAsync for an already-open session).
    public partial class QueryEditor
    {
        partial void PrepareRequest(System.Net.Http.HttpClient client, System.Net.Http.HttpRequestMessage request, string url)
        {
            // The URL alone never carries which project/language a session belongs to (that's in the
            // POST body, or implicit in the session id for later calls) —
            // QueryEditorClient._currentSessionSubject is set by whoever is opening/using that session,
            // so fold it in here if present.
            string subject = Checkmarx.API.AST.QueryEditorClient._currentSessionSubject.Value;
            Checkmarx.API.AST.QueryEditorClient._currentRequestDescription.Value =
                $"QueryEditor {request.Method} {url}" + (string.IsNullOrEmpty(subject) ? "" : $" [{subject}]");
        }
    }
}
