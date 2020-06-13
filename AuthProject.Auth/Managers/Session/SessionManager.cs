using System.Threading.Tasks;
using AuthProject.Auth.Managers.Session.Stores.Base;
using AuthProject.Auth.Models.Identity;
using AuthProject.Auth.Models.TokenPairs;
using AuthProject.Auth.Providers;
using Microsoft.AspNetCore.Identity;

namespace AuthProject.Auth.Managers.Session
{
    public class SessionManager : ISessionManager
    {
        #region Private Fields

        private readonly ISessionStore _store;
        private readonly UserManager<AppUser> _userManager;

        #endregion
        
        #region Constructor

        protected SessionManager(
            ISessionStore store, 
            UserManager<AppUser> userManager)
        {
            _store = store;
            _userManager = userManager;
        }

        #endregion

        #region Public Methods

        public virtual async Task<EncodedTokenPair> StartSessionAsync(AppUser user)
        {
            var accessToken = await _userManager.GenerateUserTokenAsync(user, ProviderConstants.AccessTokenProvider, ProviderConstants.Generate);
            var refreshToken = await _userManager.GenerateUserTokenAsync(user, ProviderConstants.RefreshTokenProvider, ProviderConstants.Generate);
           
            var tokenPair = new EncodedTokenPair()
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken
            };

            await _store.AddAsync(user, tokenPair);
            return tokenPair;
        }

        public virtual async Task EndSessionAsync(string userName)
        {
            await _store.RemoveAsync(userName);
            await Task.CompletedTask;
        }

        public virtual async Task<EncodedTokenPair> UpdateSessionAsync(AppUser user)
        {
            await EndSessionAsync(user.UserName);
            return await StartSessionAsync(user);
        }

        public async Task<bool> IsTokenPairInUse(EncodedTokenPair tokenPair)
        {
            return await _store.IsTokenPairExists(tokenPair);
        }

        public async Task<bool> IsAppUserInSession(string userName)
        {
            return await _store.IsAppUserInSession(userName);
        }

        #endregion
    }
}