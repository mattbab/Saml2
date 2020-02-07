using System.Text;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

using Sustainsys.Saml2.WebSso;

namespace Sustainsys.Saml2.AspNetCore2
{
    static class CommandResultExtensions
    {
        public static async Task Apply(
            this CommandResult commandResult,
            HttpContext httpContext,
            IRequestStateStore requestStateStore,
            string signInScheme,
            string signOutScheme)
        {
            httpContext.Response.StatusCode = (int)commandResult.HttpStatusCode;

            if(commandResult.Location != null)
            {
                httpContext.Response.Headers["Location"] = commandResult.Location.OriginalString;
            }

            if(!string.IsNullOrEmpty(commandResult.SetCookieName))
            {
                requestStateStore?.SetState(commandResult.SetCookieName, commandResult.RequestState);
            }

            foreach(var h in commandResult.Headers)
            {
                httpContext.Response.Headers.Add(h.Key, h.Value);
            }

            if(!string.IsNullOrEmpty(commandResult.ClearCookieName))
            {
                httpContext.Response.Cookies.Delete(commandResult.ClearCookieName);
            }

            if(!string.IsNullOrEmpty(commandResult.Content))
            {
                var buffer = Encoding.UTF8.GetBytes(commandResult.Content);
                httpContext.Response.ContentType = commandResult.ContentType;
                await httpContext.Response.Body.WriteAsync(buffer, 0, buffer.Length);
            }

            if(commandResult.Principal != null)
            {
                var authProps = new AuthenticationProperties(commandResult.RelayData)
                {
                    RedirectUri = commandResult.Location.OriginalString
                };
                await httpContext.SignInAsync(signInScheme, commandResult.Principal, authProps);
            }

            if(commandResult.TerminateLocalSession)
            {
                await httpContext.SignOutAsync(signOutScheme ?? signInScheme);
            }
        }
    }
}
