using AuthProject.Auth.Managers.Session.Stores.Headers;
using AuthProject.Auth.Models.Identity;
using Microsoft.AspNetCore.Identity;

namespace AuthProject.Auth.Managers.Session.Implementations.HeadersSession
{
    public class HeadersSessionManager : SessionManager, IHeadersSessionManager
    {
        public HeadersSessionManager(
            IHeadersSessionStore store, 
            UserManager<AppUser> userManager) : base(store, userManager)
        {
            
        }
    }
}