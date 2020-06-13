using System.Threading.Tasks;
using AuthProject.Auth.AuthHandlers.CookieBased;
using AuthProject.Auth.Managers.Session.Stores.Cookie;
using AuthProject.Auth.Models.Identity;
using AuthProject.Auth.Models.TokenPairs;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Newtonsoft.Json;

namespace AuthProject.Auth.Managers.Session.Implementations.CookieSession
{
    public class CookieSessionManager : SessionManager, ICookieSessionManager
    {
        #region Private Fields
        
        private readonly IHttpContextAccessor _contextAccessor;
        private readonly ICookieSessionStore _store;

        #endregion

        #region Constructor

        public CookieSessionManager(
            UserManager<AppUser> userManager, 
            IHttpContextAccessor contextAccessor,
            ICookieSessionStore store) : base(store, userManager)
        {
            _contextAccessor = contextAccessor;
            _store = store;
        }

        #endregion

        #region Public Methods

        public override async Task<EncodedTokenPair> StartSessionAsync(AppUser user)
        {
            if (await _store.IsAppUserInSession(user.UserName))
            {
                await _store.RemoveAsync(user.UserName);
            }
            
            var tokenPair = await base.StartSessionAsync(user);
            var serializedJwt = JsonConvert.SerializeObject(tokenPair);
            
            CookieManager.CreateCookie(_contextAccessor, serializedJwt);
            
            return tokenPair;
        }

        public override async Task EndSessionAsync(string user)
        {
            await base.EndSessionAsync(user);
            CookieManager.DeleteCookie(_contextAccessor);
            await Task.CompletedTask;
        }

        public override async Task<EncodedTokenPair> UpdateSessionAsync(AppUser user)
        {
            await EndSessionAsync(user.UserName);
            var newTokenPair = await StartSessionAsync(user);
            var serializedTokenPair = JsonConvert.SerializeObject(newTokenPair);
            CookieManager.UpdateCookie(_contextAccessor, serializedTokenPair);
            return newTokenPair;
        }

        #endregion
    }
}