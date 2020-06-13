using System;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using System.Web;
using AuthProject.Auth.AuthHandlers.Base;
using AuthProject.Auth.AuthHandlers.CookieBased.Constants;
using AuthProject.Auth.Managers.Session.Implementations.CookieSession;
using AuthProject.Auth.Managers.Token;
using AuthProject.Auth.Models.Identity;
using AuthProject.Auth.Models.TokenPairs;
using AuthProject.Auth.Providers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace AuthProject.Auth.AuthHandlers.CookieBased.Handler
{
    public class CookieAuthHandler : BaseAuthHandler<CookieAuthOptions>
    {
        #region Private fields

        private readonly UserManager<AppUser> _userManager;
        private readonly ITokenDecoder _tokenDecoder;
        private readonly ICookieSessionManager _jwtCookieSessionManager;
        private readonly ILogger<CookieAuthHandler> _logger;
        
        #endregion

        #region Constructor
        
        public CookieAuthHandler(
            UserManager<AppUser> userManager,
            IOptionsMonitor<CookieAuthOptions> options,
            ILoggerFactory loggerFactory,
            UrlEncoder encoder,
            ISystemClock clock,
            ITokenDecoder tokenDecoder,
            ICookieSessionManager jwtCookieSessionManager,
            ILogger<CookieAuthHandler> logger) : base(options, loggerFactory, encoder, clock, userManager, tokenDecoder)
        {
            _userManager = userManager;
            _tokenDecoder = tokenDecoder;
            _jwtCookieSessionManager = jwtCookieSessionManager;
            _logger = logger;
        }
        
        #endregion

        #region Authentication logic
        
        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (Request.Cookies.TryGetValue(CookieConstants.CookieName, out var jwt))
            {
                try
                {
                    var encodedTokenPair = ExtractTokenPairFromCookie(jwt);
                    TokenPair = encodedTokenPair;
                    
                    if (!await IsTokenPairInUse(encodedTokenPair))
                    {
                        return await Task.FromResult(AuthenticateResult.Fail("Unauthorized"));
                    }

                    return await base.HandleAuthenticateAsync();
                }

                catch (SecurityTokenExpiredException ex)
                {
                    try
                    {
                        var checkResult = await _userManager.VerifyUserTokenAsync(
                            new AppUser(),
                            ProviderConstants.RefreshTokenProvider, 
                            ProviderConstants.Verify, 
                            TokenPair.RefreshToken);

                        var userName = (string) _tokenDecoder.DecodeTokenPair(TokenPair).RefreshToken.Payload["UserName"];
                        var appUser = await _userManager.FindByNameAsync(userName);
                    
                        if (!checkResult)
                        {
                            await _jwtCookieSessionManager.EndSessionAsync(userName);
                            return await Task.FromResult(AuthenticateResult.Fail("Unauthorized"));
                        }
                        
                        await UpdateTokenPairForSession(appUser);
                    
                        var ticket = await CreateAuthenticationTicket(appUser, Scheme);
                        if (ticket == null)
                        {
                            return await Task.FromResult(AuthenticateResult.Fail("Unauthorized"));
                        }

                        return await Task.FromResult(AuthenticateResult.Success(ticket));
                    }
                    
                    catch (Exception e)
                    {
                        return await EndSession(e);
                    }
                }
                
                catch (Exception e)
                {
                    return await EndSession(e);
                }
            }
            return await Task.FromResult(AuthenticateResult.Fail("Unauthorized"));
        }
        
        #endregion

        #region Private Methods

        private async Task UpdateTokenPairForSession(AppUser user)
        {
            await _jwtCookieSessionManager.UpdateSessionAsync(user);
        }

        private async Task<bool> IsTokenPairInUse(EncodedTokenPair encodedTokenPair)
        {
            return await _jwtCookieSessionManager.IsTokenPairInUse(encodedTokenPair);
        }

        private EncodedTokenPair ExtractTokenPairFromCookie(string jwtCookie)
        {
            var decodedJson = HttpUtility.UrlDecode(jwtCookie);
            return JsonConvert.DeserializeObject<EncodedTokenPair>(decodedJson);
        }

        private async Task<AuthenticateResult> EndSession(Exception e)
        {
            var userName = (string) _tokenDecoder.DecodeTokenPair(TokenPair).RefreshToken.Payload["UserName"];
                    
            _logger.LogError($"User {userName} Authentication error \n Exception Message: {e.Message} \n StackTrace: {e.StackTrace}");

            await _jwtCookieSessionManager.EndSessionAsync(userName);
            return await Task.FromResult(AuthenticateResult.Fail("Unauthorized"));
        } 
        
        #endregion 
    }
}