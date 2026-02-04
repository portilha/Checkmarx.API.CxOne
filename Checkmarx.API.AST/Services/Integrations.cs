using Checkmarx.API.AST.Exceptions;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Checkmarx.API.AST.Services
{
    using Checkmarx.API.AST.Errors;
    using Checkmarx.API.AST.Exceptions;
    using Checkmarx.API.AST.Models;
    using System.Net.Mail;
    using static Checkmarx.API.AST.ASTClient;
    using System = global::System;

    public partial class Integrations
    {
#pragma warning disable 8618
        private string _baseUrl;
#pragma warning restore 8618

        private System.Net.Http.HttpClient _httpClient;
        private static System.Lazy<Newtonsoft.Json.JsonSerializerSettings> _settings = new System.Lazy<Newtonsoft.Json.JsonSerializerSettings>(CreateSerializerSettings, true);

#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.

        public Integrations(System.Uri aSTServer, System.Net.Http.HttpClient httpClient)
#pragma warning restore CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
        {
            BaseUrl = $"{aSTServer.AbsoluteUri}api/feedback-app";
            _httpClient = httpClient;
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

        public virtual async System.Threading.Tasks.Task<System.Collections.Generic.ICollection<ProjectProfiles>> GetProjectProfilesAsync(System.Threading.CancellationToken cancellationToken = default)
        {
            var client_ = _httpClient;
            var disposeClient_ = false;
            try
            {
                using (var request_ = new System.Net.Http.HttpRequestMessage())
                {
                    request_.Method = new System.Net.Http.HttpMethod("GET");
                    request_.Headers.Accept.Add(System.Net.Http.Headers.MediaTypeWithQualityHeaderValue.Parse("application/json"));

                    var urlBuilder_ = new System.Text.StringBuilder();
                    if (!string.IsNullOrEmpty(_baseUrl))
                        urlBuilder_.Append(_baseUrl);

                    urlBuilder_.Append("projects/profiles");

                    PrepareRequest(client_, request_, urlBuilder_);

                    var url_ = urlBuilder_.ToString();
                    request_.RequestUri = new System.Uri(url_, System.UriKind.RelativeOrAbsolute);

                    PrepareRequest(client_, request_, url_);

                    var response_ = await _retryPolicy.ExecuteAsync(() => client_.SendAsync(CloneHttpRequestMessage(request_), System.Net.Http.HttpCompletionOption.ResponseHeadersRead, cancellationToken)).ConfigureAwait(false);
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
                            var objectResponse_ = await ReadObjectResponseAsync<System.Collections.Generic.ICollection<ProjectProfiles>>(response_, headers_, cancellationToken).ConfigureAwait(false);
                            if (objectResponse_.Object == null)
                            {
                                throw new ApiException("Response was null which was not expected.", status_, objectResponse_.Text, headers_, null);
                            }
                            return objectResponse_.Object;
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

        public virtual async System.Threading.Tasks.Task<ProfilesCollection> GetProfilesAsync(int page = 1, int limit = 25, System.Threading.CancellationToken cancellationToken = default)
        {
            var urlBuilder_ = new System.Text.StringBuilder();


#if DEBUG
            urlBuilder_.Append(BaseUrl != null ? BaseUrl.TrimEnd('/') : "").Append("/profiles?");
#else
            urlBuilder_.Append(BaseUrl != null ? BaseUrl.TrimEnd('/') : "").Append("/profiles/?"); 
#endif

            urlBuilder_.Append(System.Uri.EscapeDataString("page") + "=").Append(System.Uri.EscapeDataString(ConvertToString(page, System.Globalization.CultureInfo.InvariantCulture))).Append("&");

            urlBuilder_.Append(System.Uri.EscapeDataString("limit") + "=").Append(System.Uri.EscapeDataString(ConvertToString(limit, System.Globalization.CultureInfo.InvariantCulture)));

            var client_ = _httpClient;
            var disposeClient_ = false;
            try
            {
                using (var request_ = new System.Net.Http.HttpRequestMessage())
                {
                    request_.Method = new System.Net.Http.HttpMethod("GET");

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
                            var objectResponse_ = await ReadObjectResponseAsync<ProfilesCollection>(response_, headers_, cancellationToken).ConfigureAwait(false);
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


        public IEnumerable<MailAddress> GetMailAddressesForCVENotification(Guid projectId)
        {
            var projectProfiles = GetProjectProfiles();

            var emailstoNotify = GetEmailsToNotifyForSCANewVuln();

            if (projectProfiles.ContainsKey(projectId))
            {
                // get project profile.
                var profileName = projectProfiles[projectId];

                // get the emails to notify
                if (!emailstoNotify.ContainsKey(profileName))
                    return [];

                return emailstoNotify[profileName].Select(x => new MailAddress(x));
            }

            return [];
        }


        public Dictionary<Guid, string> GetProjectProfiles()
        {
            Dictionary<Guid, string> projectProfiles = [];

            foreach (var app in GetProjectProfilesAsync().Result)
            {
                if (string.IsNullOrWhiteSpace(app.ProfileName))
                    continue;

                projectProfiles.Add(app.ProjectId, app.ProfileName);
            }

            return projectProfiles;
        }

        public Dictionary<string, ICollection<string>> GetEmailsToNotifyForSCANewVuln()
        {
            // is the profile id case sensitive?
            Dictionary<string, ICollection<string>> profileEmails = new Dictionary<string, ICollection<string>>(StringComparer.InvariantCulture);

            foreach (var profile in GetProfilesAsync().Result.Profiles)
            {
                var list = new List<string>();

                foreach (var feedbackApp in profile.FeedbackAppDtos)
                {
                    if (feedbackApp.Type != "Email")
                        continue;

                    var app = GetFeedbackAppAsync(feedbackApp.Id).Result;

                    if (app.TriggerCondition != "SCA_NEW_VULN")
                        continue;

                    list.AddRange(app.Configuration.Emails);
                }

                if (list.Any())
                    profileEmails.Add(profile.Name, list);
            }

            return profileEmails;
        }

        public virtual async System.Threading.Tasks.Task<FeedbackAppConfiguration> GetFeedbackAppAsync(int feedbackAppId, System.Threading.CancellationToken cancellationToken = default)
        {
            var urlBuilder_ = new System.Text.StringBuilder();
            urlBuilder_.Append(BaseUrl != null ? BaseUrl.TrimEnd('/') : "").Append("/apps/");
            urlBuilder_.Append(feedbackAppId);

            var client_ = _httpClient;
            var disposeClient_ = false;
            try
            {
                using (var request_ = new System.Net.Http.HttpRequestMessage())
                {
                    request_.Method = new System.Net.Http.HttpMethod("GET");

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
                            var objectResponse_ = await ReadObjectResponseAsync<FeedbackAppConfiguration>(response_, headers_, cancellationToken).ConfigureAwait(false);
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

        public virtual async System.Threading.Tasks.Task<FeedbackAppsCollection> GetFeedbackAppCollectionAsync(int page = 1, int limit = 25, System.Threading.CancellationToken cancellationToken = default)
        {
            var urlBuilder_ = new System.Text.StringBuilder();
#if DEBUG
            urlBuilder_.Append(BaseUrl != null ? BaseUrl.TrimEnd('/') : "").Append("/v2/apps?");
#else 
            urlBuilder_.Append(BaseUrl != null ? BaseUrl.TrimEnd('/') : "").Append("/v2/apps/?");
#endif

            urlBuilder_.Append(System.Uri.EscapeDataString("page") + "=").Append(System.Uri.EscapeDataString(ConvertToString(page, System.Globalization.CultureInfo.InvariantCulture))).Append("&");

            urlBuilder_.Append(System.Uri.EscapeDataString("limit") + "=").Append(System.Uri.EscapeDataString(ConvertToString(limit, System.Globalization.CultureInfo.InvariantCulture)));

            var client_ = _httpClient;
            var disposeClient_ = false;
            try
            {
                using (var request_ = new System.Net.Http.HttpRequestMessage())
                {
                    request_.Method = new System.Net.Http.HttpMethod("GET");

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
                            var objectResponse_ = await ReadObjectResponseAsync<FeedbackAppsCollection>(response_, headers_, cancellationToken).ConfigureAwait(false);
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

    public class ProjectProfiles
    {
        [JsonProperty("id", NullValueHandling = NullValueHandling.Ignore)]
        public Guid ProjectId { get; set; }

        [JsonProperty("name", NullValueHandling = NullValueHandling.Ignore)]
        public string ProjectName { get; set; }

        [JsonProperty("profileName", NullValueHandling = NullValueHandling.Ignore)]
        public string ProfileName { get; set; }
    }

    public class FeedbackAppDto
    {
        [JsonProperty("id", NullValueHandling = NullValueHandling.Ignore)]
        public int Id { get; set; }

        [JsonProperty("name", NullValueHandling = NullValueHandling.Ignore)]
        public string Name { get; set; }

        [JsonProperty("type", NullValueHandling = NullValueHandling.Ignore)]
        public string Type { get; set; }

        [JsonProperty("icon", NullValueHandling = NullValueHandling.Ignore)]
        public object Icon { get; set; }

        [JsonProperty("description", NullValueHandling = NullValueHandling.Ignore)]
        public string Description { get; set; }

        [JsonProperty("tags", NullValueHandling = NullValueHandling.Ignore)]
        public object Tags { get; set; }

        [JsonProperty("filters", NullValueHandling = NullValueHandling.Ignore)]
        public Filters Filters { get; set; }

        [JsonProperty("updatedAt", NullValueHandling = NullValueHandling.Ignore)]
        public DateTimeOffset UpdatedAt { get; set; }

        [JsonProperty("createdAt", NullValueHandling = NullValueHandling.Ignore)]
        public DateTimeOffset CreatedAt { get; set; }

        [JsonProperty("triggerCondition", NullValueHandling = NullValueHandling.Ignore)]
        public object TriggerCondition { get; set; }

        [JsonProperty("externalId", NullValueHandling = NullValueHandling.Ignore)]
        public Guid ExternalId { get; set; }
    }

    public class Filters
    {
        [JsonProperty("state", NullValueHandling = NullValueHandling.Ignore)]
        public List<string> State { get; } = new List<string>();

        [JsonProperty("engines", NullValueHandling = NullValueHandling.Ignore)]
        public List<string> Engines { get; } = new List<string>();

        [JsonProperty("severity", NullValueHandling = NullValueHandling.Ignore)]
        public List<string> Severity { get; } = new List<string>();

        [JsonProperty("directPath", NullValueHandling = NullValueHandling.Ignore)]
        public List<object> DirectPath { get; } = new List<object>();

        [JsonProperty("cwe", NullValueHandling = NullValueHandling.Ignore)]
        public List<object> Cwe { get; } = new List<object>();
    }

    public class Profile
    {
        [JsonProperty("id", NullValueHandling = NullValueHandling.Ignore)]
        public int Id { get; set; }

        [JsonProperty("name", NullValueHandling = NullValueHandling.Ignore)]
        public string Name { get; set; }

        [JsonProperty("description", NullValueHandling = NullValueHandling.Ignore)]
        public string Description { get; set; }

        [JsonProperty("tags", NullValueHandling = NullValueHandling.Ignore)]
        public object Tags { get; set; }

        [JsonProperty("projectsIds", NullValueHandling = NullValueHandling.Ignore)]
        public List<Guid> ProjectsIds { get; } = new List<Guid>();

        [JsonProperty("appsIds", NullValueHandling = NullValueHandling.Ignore)]
        public object AppsIds { get; set; }

        [JsonProperty("feedbackAppDtos", NullValueHandling = NullValueHandling.Ignore)]
        public List<FeedbackAppDto> FeedbackAppDtos { get; } = new List<FeedbackAppDto>();

        [JsonProperty("updatedAt", NullValueHandling = NullValueHandling.Ignore)]
        public DateTime UpdatedAt { get; set; }

        [JsonProperty("createdAt", NullValueHandling = NullValueHandling.Ignore)]
        public DateTime CreatedAt { get; set; }
    }

    public class ProfilesCollection
    {
        [JsonProperty("profiles", NullValueHandling = NullValueHandling.Ignore)]
        public List<Profile> Profiles { get; } = new List<Profile>();

        [JsonProperty("totalCount", NullValueHandling = NullValueHandling.Ignore)]
        public int TotalCount { get; set; }

        [JsonProperty("filteredTotalCount", NullValueHandling = NullValueHandling.Ignore)]
        public int FilteredTotalCount { get; set; }
    }

    public class EmailConfiguration
    {
        [JsonProperty("emails", NullValueHandling = NullValueHandling.Ignore)]
        public List<string> Emails { get; } = new List<string>();
    }

    public class FeedbackAppFilters
    {
        [JsonProperty("state", NullValueHandling = NullValueHandling.Ignore)]
        public List<object> State { get; } = new List<object>();

        [JsonProperty("engines", NullValueHandling = NullValueHandling.Ignore)]
        public List<string> Engines { get; } = new List<string>();

        [JsonProperty("severity", NullValueHandling = NullValueHandling.Ignore)]
        public List<string> Severity { get; } = new List<string>();

        [JsonProperty("directPath", NullValueHandling = NullValueHandling.Ignore)]
        public List<object> DirectPath { get; } = new List<object>();

        [JsonProperty("cwe", NullValueHandling = NullValueHandling.Ignore)]
        public List<object> Cwe { get; } = new List<object>();
    }

    public class FeedbackAppConfiguration
    {
        [JsonProperty("id", NullValueHandling = NullValueHandling.Ignore)]
        public int Id { get; set; }

        [JsonProperty("name", NullValueHandling = NullValueHandling.Ignore)]
        public string Name { get; set; }

        [JsonProperty("type", NullValueHandling = NullValueHandling.Ignore)]
        public string Type { get; set; }

        [JsonProperty("icon", NullValueHandling = NullValueHandling.Ignore)]
        public object Icon { get; set; }

        [JsonProperty("description", NullValueHandling = NullValueHandling.Ignore)]
        public string Description { get; set; }

        [JsonProperty("tags", NullValueHandling = NullValueHandling.Ignore)]
        public object Tags { get; set; }

        [JsonProperty("filters", NullValueHandling = NullValueHandling.Ignore)]
        public Filters Filters { get; set; }

        [JsonProperty("updatedAt", NullValueHandling = NullValueHandling.Ignore)]
        public DateTimeOffset UpdatedAt { get; set; }

        [JsonProperty("createdAt", NullValueHandling = NullValueHandling.Ignore)]
        public DateTimeOffset CreatedAt { get; set; }

        [JsonProperty("triggerCondition", NullValueHandling = NullValueHandling.Ignore)]
        public string TriggerCondition { get; set; }

        [JsonProperty("externalId", NullValueHandling = NullValueHandling.Ignore)]
        public Guid ExternalId { get; set; }

        [JsonProperty("configuration", NullValueHandling = NullValueHandling.Ignore)]
        public EmailConfiguration Configuration { get; set; }
    }

    public class FeedbackAppDefinition
    {
        [JsonProperty("id", NullValueHandling = NullValueHandling.Ignore)]
        public int Id { get; set; }

        [JsonProperty("name", NullValueHandling = NullValueHandling.Ignore)]
        public string Name { get; set; }

        [JsonProperty("type", NullValueHandling = NullValueHandling.Ignore)]
        public string Type { get; set; }

        [JsonProperty("icon", NullValueHandling = NullValueHandling.Ignore)]
        public object Icon { get; set; }

        [JsonProperty("description", NullValueHandling = NullValueHandling.Ignore)]
        public string Description { get; set; }

        [JsonProperty("tags", NullValueHandling = NullValueHandling.Ignore)]
        public object Tags { get; set; }

        [JsonProperty("filters", NullValueHandling = NullValueHandling.Ignore)]
        public Filters Filters { get; set; }

        [JsonProperty("updatedAt", NullValueHandling = NullValueHandling.Ignore)]
        public DateTime UpdatedAt { get; set; }

        [JsonProperty("createdAt", NullValueHandling = NullValueHandling.Ignore)]
        public DateTime CreatedAt { get; set; }

        [JsonProperty("triggerCondition", NullValueHandling = NullValueHandling.Ignore)]
        public string TriggerCondition { get; set; }

        [JsonProperty("externalId", NullValueHandling = NullValueHandling.Ignore)]
        public string ExternalId { get; set; }
    }

    public class FeedbackAppsCollection
    {
        [JsonProperty("apps", NullValueHandling = NullValueHandling.Ignore)]
        public List<FeedbackAppDto> Apps { get; } = new List<FeedbackAppDto>();

        [JsonProperty("filteredTotalCount", NullValueHandling = NullValueHandling.Ignore)]
        public int FilteredTotalCount { get; set; }
    }




}
