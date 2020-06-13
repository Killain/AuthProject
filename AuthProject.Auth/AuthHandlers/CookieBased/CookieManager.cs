using System.Web;
using AuthProject.Auth.AuthHandlers.CookieBased.Constants;
using Microsoft.AspNetCore.Http;

namespace AuthProject.Auth.AuthHandlers.CookieBased
{
    public class CookieManager
    {
        private static readonly string _cookieName = CookieConstants.CookieName;
        
        public static void CreateCookie(IHttpContextAccessor contextAccessor, string tokenPair)
        {
            contextAccessor.HttpContext.Response.Cookies.Append(_cookieName,
                HttpUtility.UrlEncode(tokenPair),
                new CookieOptions
                {
                    HttpOnly = true
                });
        }

        public static void DeleteCookie(IHttpContextAccessor contextAccessor)
        {
            contextAccessor.HttpContext.Response.Cookies.Delete(_cookieName);
        }

        public static void UpdateCookie(IHttpContextAccessor contextAccessor, string tokenPair) {
            DeleteCookie(contextAccessor);
            CreateCookie(contextAccessor, tokenPair);
        }
    }
}