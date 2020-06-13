using System;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using AuthProject.Auth.AuthHandlers.Base;
using AuthProject.Auth.Managers.Session.Implementations.HeadersSession;
using AuthProject.Auth.Managers.Token;
using AuthProject.Auth.Models.Identity;
using AuthProject.Auth.Models.TokenPairs;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;

namespace AuthProject.Auth.AuthHandlers.HeadersBased
{
    public class HeadersAuthHandler : BaseAuthHandler<JwtAuthOptions>
    {
        #region Private Fields

        private readonly IHeadersSessionManager _sessionManager;
        private readonly ILogger<HeadersAuthHandler> _logger;

        #endregion

        #region Constructor
        public HeadersAuthHandler(UserManager<AppUser> userManager,
            IOptionsMonitor<JwtAuthOptions> options,
            ILoggerFactory loggerFactory,
            UrlEncoder encoder,
            ISystemClock clock,
            ITokenDecoder tokenDecoder,
            IHeadersSessionManager sessionManager,
            ILogger<HeadersAuthHandler> logger) : base(options, loggerFactory, encoder, clock, userManager, tokenDecoder)
        {
            _sessionManager = sessionManager;
            _logger = logger;
        }
        
        #endregion

        #region Authentication logic
        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.ContainsKey("Authorization"))
            {
                return await Task.FromResult(AuthenticateResult.Fail("Unauthorized"));
            }

            string authorizationHeader = Request.Headers["Authorization"];

            if (!string.IsNullOrEmpty(authorizationHeader))
            {
                try
                {
                    var encodedTokenPair = JsonConvert.DeserializeObject<EncodedTokenPair>(Request.Headers["Authorization"]);
                    
                    if (!await IsTokenPairInUse(encodedTokenPair))
                    {
                        return await Task.FromResult(AuthenticateResult.Fail("Unauthorized"));
                    }

                    TokenPair = encodedTokenPair;
                    
                    return await base.HandleAuthenticateAsync();
                }
                
                catch (Exception e)
                {
                    _logger.LogError($"User Authentication error \n Exception Message: {e.Message}  \n StackTrace: {e.StackTrace}");
                    return await Task.FromResult(AuthenticateResult.Fail("Unauthorized"));
                }
            }
            return await Task.FromResult(AuthenticateResult.Fail("Unauthorized"));
        }
        #endregion

        #region Private Methods

        private async Task<bool> IsTokenPairInUse(EncodedTokenPair encodedTokenPair)
        {
            return await _sessionManager.IsTokenPairInUse(encodedTokenPair);
        }
        
        #endregion
    }
}