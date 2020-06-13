using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using AuthProject.Auth.Managers.Token;
using AuthProject.Auth.Models.Identity;
using AuthProject.Auth.Models.TokenPairs;
using AuthProject.Auth.Providers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AuthProject.Auth.AuthHandlers.Base
{
    public abstract class BaseAuthHandler<TOptions> : AuthenticationHandler<TOptions> where TOptions : AuthenticationSchemeOptions, new()
    {
        #region Private fields

        private readonly UserManager<AppUser> _userManager;
        private readonly ITokenDecoder _tokenDecoder;

        #endregion

        #region Protected fields

        protected EncodedTokenPair TokenPair { get; set; }

        #endregion

        #region Constructor

        protected BaseAuthHandler(
            IOptionsMonitor<TOptions> options, 
            ILoggerFactory loggerFactory, 
            UrlEncoder encoder, 
            ISystemClock clock,
            UserManager<AppUser> userManager,
            ITokenDecoder tokenDecoder) : base(options, loggerFactory, encoder, clock)
        {
            _userManager = userManager;
            _tokenDecoder = tokenDecoder;
        }

        #endregion

        #region Protected methods
        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var checkResult = await _userManager.VerifyUserTokenAsync(
                new AppUser(),
                ProviderConstants.AccessTokenProvider, 
                ProviderConstants.Verify, 
                TokenPair.AccessToken);

            if (!checkResult)
            {
                return await Task.FromResult(AuthenticateResult.Fail("Unauthorized"));
            }
            
            var accessToken = _tokenDecoder.DecodeTokenPair(TokenPair).AccessToken;
            var user = await _userManager.FindByNameAsync((string) accessToken.Payload["UserName"]);
            
            var ticket = await CreateAuthenticationTicket(user, Scheme);
            if (ticket == null)
            {
                return await Task.FromResult(AuthenticateResult.Fail("Unauthorized"));
            }

            return await Task.FromResult(AuthenticateResult.Success(ticket));
        }
        
        protected async Task<AuthenticationTicket> CreateAuthenticationTicket(AppUser user, AuthenticationScheme scheme)
        {
            var claims = await _userManager.GetClaimsAsync(user);
            var roles = await _userManager.GetRolesAsync(user);

            var identity = new ClaimsIdentity(claims, scheme.Name);
            var principal = new GenericPrincipal(identity, roles.ToArray());
            
            var ticket = new AuthenticationTicket(principal, scheme.Name);

            return ticket;
        }

        #endregion
    }
}