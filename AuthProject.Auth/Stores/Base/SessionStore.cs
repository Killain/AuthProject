using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthProject.Auth.Models.Identity;
using AuthProject.Auth.Models.TokenPairs;

namespace AuthProject.Auth.Managers.Session.Stores.Base
{
    public class SessionStore : ISessionStore
    {
        #region Private Fields

        private readonly Dictionary<EncodedTokenPair, AppUser> _sessions;

        #endregion

        #region Constructor

        protected SessionStore()
        {
            _sessions = new Dictionary<EncodedTokenPair, AppUser>();
        }

        #endregion

        #region Public Methods
        
        public Task AddAsync(AppUser user, EncodedTokenPair tokenPair)
        {
            _sessions.Add(tokenPair, user);
            return Task.CompletedTask;
        }

        public Task RemoveAsync(string userName)
        {
            _sessions.Remove
            (
                _sessions.FirstOrDefault
                    (
                        x => x.Value.UserName.Equals(userName, StringComparison.OrdinalIgnoreCase)
                    )
                    .Key
            );
            return Task.CompletedTask;
        }

        public async Task UpdateAsync(AppUser user, EncodedTokenPair tokenPair)
        {
            await RemoveAsync(user.UserName);
            await AddAsync(user, tokenPair);
            await Task.CompletedTask;
        }

        public Task<bool> IsTokenPairExists(EncodedTokenPair encodedTokenPair)
        {
            return Task.FromResult
            (
                _sessions.Any
                (
                    x => x.Key.RefreshToken.Equals(encodedTokenPair.RefreshToken, StringComparison.OrdinalIgnoreCase)
                )
            );
        }

        public async Task<bool> IsAppUserInSession(string userName)
        {
            return await Task.FromResult
            (
                _sessions.Any
                (
                    x => x.Value.UserName.Equals(userName, StringComparison.OrdinalIgnoreCase)
                )
            );
        }

        #endregion
    }
}