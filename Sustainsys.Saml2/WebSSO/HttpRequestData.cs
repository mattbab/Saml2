﻿using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Security.Claims;

using Sustainsys.Saml2.Internal;

namespace Sustainsys.Saml2.WebSso
{
    /// <summary>
    /// The data of a http request that Saml2 needs to handle. A separate DTO is used
    /// to make the core library totally independent of the hosting environment.
    /// </summary>
    public class HttpRequestData
    {
        /// <summary>
        /// Ctor
        /// </summary>
        /// <param name="httpMethod">Http method of the request</param>
        /// <param name="url">Full url requested</param>
        /// <param name="formData">Form data, if present (only for POST requests)</param>
        /// <param name="applicationPath">Path to the application root</param>
        /// <param name="requestStateStore">Storage for request state</param>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704:IdentifiersShouldBeSpelledCorrectly", MessageId = "Decryptor")]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1006:DoNotNestGenericTypesInMemberSignatures")]
        public HttpRequestData(
            string httpMethod,
            Uri url,
            string applicationPath,
            IEnumerable<KeyValuePair<string, IEnumerable<string>>> formData,
            IRequestStateStore requestStateStore)
            : this(httpMethod, url, applicationPath, formData, requestStateStore, user: null)
        {
            // empty
        }

        /// <summary>
        /// Ctor
        /// </summary>
        /// <param name="httpMethod">Http method of the request</param>
        /// <param name="url">Full url requested</param>
        /// <param name="formData">Form data, if present (only for POST requests)</param>
        /// <param name="applicationPath">Path to the application root</param>
        /// <param name="requestStateStore">Storage for request state</param>
        /// <param name="user">Claims Principal associated with the request</param>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704:IdentifiersShouldBeSpelledCorrectly", MessageId = "Decryptor")]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1006:DoNotNestGenericTypesInMemberSignatures")]
        public HttpRequestData(
            string httpMethod,
            Uri url,
            string applicationPath,
            IEnumerable<KeyValuePair<string, IEnumerable<string>>> formData,
            IRequestStateStore requestStateStore,
            ClaimsPrincipal user)
        {
            Init(httpMethod, url, applicationPath, formData, requestStateStore, user);
        }

        // Used by tests.
        internal HttpRequestData(string httpMethod, Uri url)
        {
            Init(httpMethod, url, "/", null, null, null);
        }

        // Used by tests.
        internal HttpRequestData(
            string httpMethod,
            Uri url,
            string applicationPath,
            IEnumerable<KeyValuePair<string, IEnumerable<string>>> formData,
            StoredRequestState storedRequestState)
        {
            InitBasicFields(httpMethod, url, applicationPath, formData);
            StoredRequestState = storedRequestState;
        }

        private void Init(
            string httpMethod,
            Uri url,
            string applicationPath,
            IEnumerable<KeyValuePair<string, IEnumerable<string>>> formData,
            IRequestStateStore requestStateStore,
            ClaimsPrincipal user)
        {
            InitBasicFields(httpMethod, url, applicationPath, formData);
            User = user;

            var relayState = QueryString["RelayState"].SingleOrDefault();
            if(relayState == null)
            {
                Form.TryGetValue("RelayState", out relayState);
            }
            RelayState = relayState;

            if (relayState != null)
            {
                var cookieName = StoredRequestState.CookieNameBase + relayState;

                StoredRequestState = requestStateStore.GetState(cookieName);
            }
        }

        internal static byte[] GetBinaryData(string cookieData)
        {
            return Convert.FromBase64String(
                cookieData
                .Replace('_', '/')
                .Replace('-', '+')
                .Replace('.', '='));
        }

        private void InitBasicFields(string httpMethod, Uri url, string applicationPath, IEnumerable<KeyValuePair<string, IEnumerable<string>>> formData)
        {
            HttpMethod = httpMethod;
            Url = url;
            ApplicationUrl = new Uri(url, applicationPath);
            Form = new ReadOnlyDictionary<string, string>(
                (formData ?? Enumerable.Empty<KeyValuePair<string, IEnumerable<string>>>())
                .ToDictionary(kv => kv.Key, kv => kv.Value.Single()));
            QueryString = QueryStringHelper.ParseQueryString(url.Query);
        }

        /// <summary>
        /// Escape a Base 64 encoded cookie value, matching the unescaping
        /// that is done in the ctor.
        /// </summary>
        /// <param name="data">Data to escape</param>
        /// <returns>Escaped data</returns>
        public static string ConvertBinaryData(byte[] data)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            return Convert.ToBase64String(data)
                .Replace('/', '_')
                .Replace('+', '-')
                .Replace('=', '.');
        }

        /// <summary>
        /// The http method of the request.
        /// </summary>
        public string HttpMethod { get; set; }

        /// <summary>
        /// The complete Url of the request.
        /// </summary>
        public Uri Url { get; set; }

        /// <summary>
        /// The form data associated with the request (if any).
        /// </summary>
        public IReadOnlyDictionary<string, string> Form { get; set; }

        /// <summary>
        /// The query string parameters of the request.
        /// </summary>
        public ILookup<String, String> QueryString { get; set; }

        /// <summary>
        /// The root Url of the application. This includes the virtual directory
        /// that the application is installed in, e.g. http://hosting.example.com/myapp/
        /// </summary>
        public Uri ApplicationUrl { get; set; }

        /// <summary>
        /// RelayState from SAML message
        /// </summary>
        public string RelayState { get; set; }

        /// <summary>
        /// Request state from a previous call, carried over through cookie.
        /// </summary>
        public StoredRequestState StoredRequestState { get; set; }

        /// <summary>
        /// User (if any) associated with the request
        /// </summary>
        public ClaimsPrincipal User { get; set; }
    }
}
