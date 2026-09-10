namespace Checkmarx.API.AST.Services.QueryEditor
{
    using System = global::System;
    using static Checkmarx.API.AST.ASTClient;
    using System.Collections.Generic;
    using System;
    using Newtonsoft.Json;
    using Checkmarx.API.AST.Exceptions;
    using Checkmarx.API.AST.Errors;

    // Hand-written companion to the NSwag-generated QueryEditor.cs (PutQueryMetadataAsync is one of
    // its generated methods, not touched by regeneration).
    //
    // PutQueryMetadataAsync(sessionId, editorQueryId, AsyncRequestResponse body) is unusable as-is:
    // per the live spec (ireland-query-editor-router-QUERY_EDITOR.yaml, "PUT
    // /sessions/{sessionId}/queries/{editorQueryId}/metadata"), the requestBody schema is genuinely
    // $ref'd to AsyncRequestResponse (just { id }) — a spec authoring bug, not an NSwag mis-generation
    // — so the generated body type carries no way to say "severity" and would force a bogus
    // all-zero "id" into the request. The spec's own example for this exact operation
    // (components.examples.putQueryMetadata_200) shows the real, working body is a partial metadata
    // patch: { "severity": "..." }. This method sends exactly that instead, reusing the same
    // session/request plumbing (PrepareRequest, ProcessResponse, retry policy) as the rest of this
    // partial class so it behaves identically to every other QueryEditor call under session-limit
    // retries and error handling.
    public partial class QueryEditor
    {
        public virtual async System.Threading.Tasks.Task<AsyncRequestResponse> PutQuerySeverityAsync(System.Guid sessionId, string editorQueryId, string severity, System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken))
        {
            if (editorQueryId == null)
                throw new System.ArgumentNullException("editorQueryId");

            if (string.IsNullOrWhiteSpace(severity))
                throw new System.ArgumentNullException("severity");

            var client_ = _httpClient;
            var disposeClient_ = false;
            try
            {
                using (var request_ = new System.Net.Http.HttpRequestMessage())
                {
                    var json_ = Newtonsoft.Json.JsonConvert.SerializeObject(new Newtonsoft.Json.Linq.JObject { ["severity"] = severity });
                    var content_ = new System.Net.Http.StringContent(json_);
                    content_.Headers.ContentType = System.Net.Http.Headers.MediaTypeHeaderValue.Parse("application/json");
                    request_.Content = content_;
                    request_.Method = new System.Net.Http.HttpMethod("PUT");
                    request_.Headers.Accept.Add(System.Net.Http.Headers.MediaTypeWithQualityHeaderValue.Parse("application/json; version=1.0"));

                    var urlBuilder_ = new System.Text.StringBuilder();
                    if (!string.IsNullOrEmpty(_baseUrl)) urlBuilder_.Append(_baseUrl);
                    urlBuilder_.Append("sessions/");
                    urlBuilder_.Append(System.Uri.EscapeDataString(ConvertToString(sessionId, System.Globalization.CultureInfo.InvariantCulture)));
                    urlBuilder_.Append("/queries/");
                    urlBuilder_.Append(System.Uri.EscapeDataString(ConvertToString(editorQueryId, System.Globalization.CultureInfo.InvariantCulture)));
                    urlBuilder_.Append("/metadata");

                    PrepareRequest(client_, request_, urlBuilder_);

                    var url_ = urlBuilder_.ToString();
                    request_.RequestUri = new System.Uri(url_, System.UriKind.RelativeOrAbsolute);

                    PrepareRequest(client_, request_, url_);

                    var response_ = await Checkmarx.API.AST.QueryEditorClient._retryPolicy.ExecuteAsync(() => client_.SendAsync(Checkmarx.API.AST.ASTClient.CloneHttpRequestMessage(request_), System.Net.Http.HttpCompletionOption.ResponseHeadersRead, cancellationToken)).ConfigureAwait(false);
                    var disposeResponse_ = true;
                    try
                    {
                        var headers_ = new System.Collections.Generic.Dictionary<string, System.Collections.Generic.IEnumerable<string>>();
                        foreach (var item_ in response_.Headers)
                            headers_[item_.Key] = item_.Value;
                        if (response_.Content != null && response_.Content.Headers != null)
                        {
                            foreach (var item_ in response_.Content.Headers)
                                headers_[item_.Key] = item_.Value;
                        }

                        ProcessResponse(client_, response_);

                        var status_ = (int)response_.StatusCode;
                        if (status_ == 200)
                        {
                            var objectResponse_ = await ReadObjectResponseAsync<AsyncRequestResponse>(response_, headers_, cancellationToken).ConfigureAwait(false);
                            if (objectResponse_.Object == null)
                                throw new ApiException("Response was null which was not expected.", status_, objectResponse_.Text, headers_, null);
                            return objectResponse_.Object;
                        }
                        else if (status_ == 401)
                        {
                            string responseText_ = (response_.Content == null) ? string.Empty : await response_.Content.ReadAsStringAsync().ConfigureAwait(false);
                            throw new ApiException("Unauthorized, Access token is missing or invalid", status_, responseText_, headers_, null);
                        }
                        else if (status_ == 403)
                        {
                            string responseText_ = (response_.Content == null) ? string.Empty : await response_.Content.ReadAsStringAsync().ConfigureAwait(false);
                            throw new ApiException("Forbidden", status_, responseText_, headers_, null);
                        }
                        else if (status_ == 404)
                        {
                            var objectResponse_ = await ReadObjectResponseAsync<Error>(response_, headers_, cancellationToken).ConfigureAwait(false);
                            if (objectResponse_.Object == null)
                                throw new ApiException("Response was null which was not expected.", status_, objectResponse_.Text, headers_, null);
                            throw new ApiException<Error>("Not Found", status_, objectResponse_.Text, headers_, objectResponse_.Object, null);
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
    }
}
