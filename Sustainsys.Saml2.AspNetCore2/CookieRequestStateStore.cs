using System;
using System.Linq;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;

using Sustainsys.Saml2.WebSso;

namespace Sustainsys.Saml2.AspNetCore2
{
    /**
     * This is the default, backwards-compatible implementation of the IRequestStateStore interface. It stores
     * the StoredRequestState serialized in a cookie. This implementation works great as long as your scenario
     * allows for cookies to be used.
     */
    public class CookieRequestStateStore : IRequestStateStore
    {
        private readonly IHttpContextAccessor contextAccessor;
        private readonly IDataProtector dataProtector;

        /**
         */
        public CookieRequestStateStore(
            IHttpContextAccessor contextAccessor,
            IDataProtectionProvider dataProtectionProvider)
        {
            if (dataProtectionProvider == null)
            {
                throw new ArgumentNullException(nameof(dataProtectionProvider));
            }

            dataProtector = dataProtectionProvider.CreateProtector(GetType().FullName);

            this.contextAccessor = contextAccessor;
        }

        /**
         * Reads the StoredRequestState from the cookies based on the provided cookie name
         */
        public StoredRequestState GetState(string key)
        {
            var httpContext = contextAccessor.HttpContext;
            var cookies = httpContext.Request.Cookies;

            var cookieData = cookies.FirstOrDefault(c => c.Key == key).Value;
            if (!string.IsNullOrEmpty(cookieData))
            {
                byte[] encryptedData = Convert.FromBase64String(cookieData);

                var decryptedData = dataProtector.Unprotect(encryptedData);

                return new StoredRequestState(decryptedData);
            }

            return null;
        }

        /**
         * Adds the StoredRequestState to a cookie
         */
        public void SetState(string key, StoredRequestState state)
        {
            var cookieData = Convert.ToBase64String(dataProtector.Protect(state?.Serialize()));
            var httpContext = contextAccessor.HttpContext;

            httpContext.Response.Cookies.Append(
                key,
                cookieData,
                new CookieOptions()
                {
                    HttpOnly = true,
                        // We are expecting a different site to POST back to us,
                        // so the ASP.Net Core default of Lax is not appropriate in this case
                        SameSite = SameSiteMode.None,
                    IsEssential = true
                });
        }
    }
}
