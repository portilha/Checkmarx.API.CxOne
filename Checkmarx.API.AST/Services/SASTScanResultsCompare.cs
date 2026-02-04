using Checkmarx.API.AST.Errors;
using Checkmarx.API.AST.Exceptions;
using System;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using static Checkmarx.API.AST.ASTClient;

namespace Checkmarx.API.AST.Services.SASTScanResultsCompare
{
    public partial class SASTScanResultsCompare
    {
        private string _baseUrl;
        private System.Net.Http.HttpClient _httpClient;
        private static Lazy<Newtonsoft.Json.JsonSerializerSettings> _settings = new Lazy<Newtonsoft.Json.JsonSerializerSettings>(CreateSerializerSettings, true);
        private Newtonsoft.Json.JsonSerializerSettings _instanceSettings;

        public SASTScanResultsCompare(System.Uri aSTServer, System.Net.Http.HttpClient httpClient)
        {
            BaseUrl = $"{aSTServer.AbsoluteUri}api/scans-compare/sast";
            _httpClient = httpClient;
            Initialize();
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

        protected Newtonsoft.Json.JsonSerializerSettings JsonSerializerSettings { get { return _instanceSettings ?? _settings.Value; } }

        static partial void UpdateJsonSerializerSettings(Newtonsoft.Json.JsonSerializerSettings settings);

        partial void Initialize();

        partial void PrepareRequest(HttpClient client, HttpRequestMessage request, string url);
        partial void PrepareRequest(HttpClient client, HttpRequestMessage request, StringBuilder urlBuilder);
        partial void ProcessResponse(HttpClient client, HttpResponseMessage response);

        /// <param name="cancellationToken">A cancellation token that can be used by other objects or threads to receive notice of cancellation.</param>
        /// <summary>
        /// Get total counts of results per severity and status
        /// </summary>
        /// <remarks>
        /// Get total counts of results per severity and status for two given scans
        /// </remarks>
        /// <param name="authorization">JWT access token</param>
        /// <param name="correlationId">Correlation ID, used to keep track of a flow if many APIs are involved</param>
        /// <param name="accept">API version should be appended to this header</param>
        /// <param name="scan_id">Scan ID of the newer scan to compare</param>
        /// <param name="base_scan_id">Scan ID of the older scan to compare</param>
        /// <returns>Successful operation</returns>
        /// <exception cref="ApiException">A server side error occurred.</exception>
        public virtual async Task<StatsCompareResult> StatusAsync(Guid base_scan_id, Guid scan_id, string authorization = null, Guid? correlationId = null, string accept = null, System.Threading.CancellationToken cancellationToken = default)
        {
            if (scan_id == Guid.Empty)
                throw new System.ArgumentNullException("scan_id");

            if (base_scan_id == Guid.Empty)
                throw new System.ArgumentNullException("base_scan_id");

            var client_ = _httpClient;
            var disposeClient_ = false;
            try
            {
                using (var request_ = new System.Net.Http.HttpRequestMessage())
                {

                    if (authorization != null)
                        request_.Headers.TryAddWithoutValidation("Authorization", ConvertToString(authorization, System.Globalization.CultureInfo.InvariantCulture));

                    if (correlationId != null)
                        request_.Headers.TryAddWithoutValidation("CorrelationId", ConvertToString(correlationId, System.Globalization.CultureInfo.InvariantCulture));

                    if (accept != null)
                        request_.Headers.TryAddWithoutValidation("Accept", ConvertToString(accept, System.Globalization.CultureInfo.InvariantCulture));
                    request_.Method = new System.Net.Http.HttpMethod("GET");

                    var urlBuilder_ = new System.Text.StringBuilder();
                    if (!string.IsNullOrEmpty(_baseUrl)) urlBuilder_.Append(_baseUrl);
                    // Operation Path: "status"
                    urlBuilder_.Append("status");
                    urlBuilder_.Append('?');
                    urlBuilder_.Append(System.Uri.EscapeDataString("scan-id")).Append('=').Append(System.Uri.EscapeDataString(ConvertToString(scan_id, System.Globalization.CultureInfo.InvariantCulture))).Append('&');
                    urlBuilder_.Append(System.Uri.EscapeDataString("base-scan-id")).Append('=').Append(System.Uri.EscapeDataString(ConvertToString(base_scan_id, System.Globalization.CultureInfo.InvariantCulture))).Append('&');
                    urlBuilder_.Length--;

                    PrepareRequest(client_, request_, urlBuilder_);

                    var url_ = urlBuilder_.ToString();
                    request_.RequestUri = new System.Uri(url_, System.UriKind.RelativeOrAbsolute);

                    PrepareRequest(client_, request_, url_);

                    var response_ = await _retryPolicy.ExecuteAsync(() => client_.SendAsync(CloneHttpRequestMessage(request_), HttpCompletionOption.ResponseHeadersRead, cancellationToken)).ConfigureAwait(false);

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
                            var objectResponse_ = await ReadObjectResponseAsync<StatsCompareResult>(response_, headers_, cancellationToken).ConfigureAwait(false);
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
                            throw new ApiException<WebError>("Invalid request parameters supplied, check scan-id and base-scan-id", status_, objectResponse_.Text, headers_, objectResponse_.Object, null);
                        }
                        else
                        if (status_ == 403)
                        {
                            var objectResponse_ = await ReadObjectResponseAsync<WebError>(response_, headers_, cancellationToken).ConfigureAwait(false);
                            if (objectResponse_.Object == null)
                            {
                                throw new ApiException("Response was null which was not expected.", status_, objectResponse_.Text, headers_, null);
                            }
                            throw new ApiException<WebError>("No permissions to access the given scans", status_, objectResponse_.Text, headers_, objectResponse_.Object, null);
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

    [System.CodeDom.Compiler.GeneratedCode("NJsonSchema", "14.1.0.0 (NJsonSchema v11.0.2.0 (Newtonsoft.Json v13.0.0.0))")]
    public partial class StatsCompareResult
    {
        [Newtonsoft.Json.JsonProperty("severityStatusCounters", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public System.Collections.Generic.ICollection<SeverityStatusCounters> SeverityStatusCounters { get; set; }

        [Newtonsoft.Json.JsonProperty("scanCounters", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public StatsCompareScan ScanCounters { get; set; }

        [Newtonsoft.Json.JsonProperty("baseScanCounters", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public StatsCompareScan BaseScanCounters { get; set; }

        private System.Collections.Generic.IDictionary<string, object> _additionalProperties;

        [Newtonsoft.Json.JsonExtensionData]
        public System.Collections.Generic.IDictionary<string, object> AdditionalProperties
        {
            get { return _additionalProperties ?? (_additionalProperties = new System.Collections.Generic.Dictionary<string, object>()); }
            set { _additionalProperties = value; }
        }

        public double GetResultCountByStatus(Services.SASTScanResultsCompare.StatusEnumCmp status,
                                             Services.SASTScanResultsCompare.SeverityEnum? severity = null)
        {
            return SeverityStatusCounters.Where(x => severity == null || x.Severity == severity)
                                         .SelectMany(x => x.Results)
                                         .Where(x => x.Status == status)
                                         .Sum(x => x.Count);
        }
    }

    [System.CodeDom.Compiler.GeneratedCode("NJsonSchema", "14.1.0.0 (NJsonSchema v11.0.2.0 (Newtonsoft.Json v13.0.0.0))")]
    public partial class StatsCompareScan
    {
        [Newtonsoft.Json.JsonProperty("CRITICAL", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public double CRITICAL { get; set; }

        [Newtonsoft.Json.JsonProperty("HIGH", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public double HIGH { get; set; }

        [Newtonsoft.Json.JsonProperty("MEDIUM", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public double MEDIUM { get; set; }

        [Newtonsoft.Json.JsonProperty("LOW", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public double LOW { get; set; }

        [Newtonsoft.Json.JsonProperty("INFO", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public double INFO { get; set; }

        private System.Collections.Generic.IDictionary<string, object> _additionalProperties;

        [Newtonsoft.Json.JsonExtensionData]
        public System.Collections.Generic.IDictionary<string, object> AdditionalProperties
        {
            get { return _additionalProperties ?? (_additionalProperties = new System.Collections.Generic.Dictionary<string, object>()); }
            set { _additionalProperties = value; }
        }

    }

    /// <summary>
    /// Severity enum of a vulnerability
    /// </summary>
    [System.CodeDom.Compiler.GeneratedCode("NJsonSchema", "14.1.0.0 (NJsonSchema v11.0.2.0 (Newtonsoft.Json v13.0.0.0))")]
    public enum SeverityEnum
    {

        [System.Runtime.Serialization.EnumMember(Value = @"CRITICAL")]
        CRITICAL = 0,

        [System.Runtime.Serialization.EnumMember(Value = @"HIGH")]
        HIGH = 1,

        [System.Runtime.Serialization.EnumMember(Value = @"MEDIUM")]
        MEDIUM = 2,

        [System.Runtime.Serialization.EnumMember(Value = @"LOW")]
        LOW = 3,

        [System.Runtime.Serialization.EnumMember(Value = @"INFO")]
        INFO = 4,

    }

    /// <summary>
    /// Status enum of a result
    /// </summary>
    [System.CodeDom.Compiler.GeneratedCode("NJsonSchema", "14.1.0.0 (NJsonSchema v11.0.2.0 (Newtonsoft.Json v13.0.0.0))")]
    public enum StatusEnumCmp
    {

        [System.Runtime.Serialization.EnumMember(Value = @"NEW")]
        NEW = 0,

        [System.Runtime.Serialization.EnumMember(Value = @"RECURRENT")]
        RECURRENT = 1,

        [System.Runtime.Serialization.EnumMember(Value = @"FIXED")]
        FIXED = 2,

    }

    [System.CodeDom.Compiler.GeneratedCode("NJsonSchema", "14.1.0.0 (NJsonSchema v11.0.2.0 (Newtonsoft.Json v13.0.0.0))")]
    public partial class SeverityStatusCounters
    {
        [Newtonsoft.Json.JsonProperty("severity", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        [Newtonsoft.Json.JsonConverter(typeof(Newtonsoft.Json.Converters.StringEnumConverter))]
        public SeverityEnum Severity { get; set; }

        [Newtonsoft.Json.JsonProperty("results", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public System.Collections.Generic.ICollection<Results> Results { get; set; }

        private System.Collections.Generic.IDictionary<string, object> _additionalProperties;

        [Newtonsoft.Json.JsonExtensionData]
        public System.Collections.Generic.IDictionary<string, object> AdditionalProperties
        {
            get { return _additionalProperties ?? (_additionalProperties = new System.Collections.Generic.Dictionary<string, object>()); }
            set { _additionalProperties = value; }
        }

    }

    [System.CodeDom.Compiler.GeneratedCode("NJsonSchema", "14.1.0.0 (NJsonSchema v11.0.2.0 (Newtonsoft.Json v13.0.0.0))")]
    public partial class Results
    {
        [Newtonsoft.Json.JsonProperty("status", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        [Newtonsoft.Json.JsonConverter(typeof(Newtonsoft.Json.Converters.StringEnumConverter))]
        public StatusEnumCmp Status { get; set; }

        [Newtonsoft.Json.JsonProperty("count", Required = Newtonsoft.Json.Required.DisallowNull, NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
        public double Count { get; set; }

        private System.Collections.Generic.IDictionary<string, object> _additionalProperties;

        [Newtonsoft.Json.JsonExtensionData]
        public System.Collections.Generic.IDictionary<string, object> AdditionalProperties
        {
            get { return _additionalProperties ?? (_additionalProperties = new System.Collections.Generic.Dictionary<string, object>()); }
            set { _additionalProperties = value; }
        }

    }

}
