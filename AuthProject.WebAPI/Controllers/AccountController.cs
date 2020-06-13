using System;
using System.Linq;
using System.Threading.Tasks;
using AuthProject.Auth.IdentityDBContext;
using AuthProject.Auth.Managers.Session;
using AuthProject.Auth.Managers.Session.Implementations.CookieSession;
using AuthProject.Auth.Managers.Session.Implementations.HeadersSession;
using AuthProject.Auth.Managers.Token;
using AuthProject.Auth.Models.Identity;
using AuthProject.Auth.Policy;
using AuthProject.Auth.Providers;
using AuthProject.WebAPI.Role;
using AuthProject.WebAPI.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using SignInResult = Microsoft.AspNetCore.Identity.SignInResult;

namespace AuthProject.WebAPI.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AccountController : Controller
    {
        #region Private fields

        private readonly UserManager<AppUser> _userManager;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly ITokenDecoder _tokenDecoder;
        private readonly SignInManager<AppUser> _signInManager;
        private readonly ICookieSessionManager _cookieSessionManager;
        private readonly IHeadersSessionManager _headersSessionManager;
        private readonly ILogger<RefreshTokenProvider> _logger;
        private readonly UsersDbContext _dbContext;
        
        #endregion

        #region Public constructor

        public AccountController(UserManager<AppUser> userManager,
            IHttpContextAccessor httpContextAccessor,
            ITokenDecoder tokenDecoder,
            SignInManager<AppUser> signInManager,
            ICookieSessionManager cookieSessionManager,
            IHeadersSessionManager headersSessionManager,
            ILogger<RefreshTokenProvider> logger,
            UsersDbContext dbContext)
        {
            _userManager = userManager;
            _httpContextAccessor = httpContextAccessor;
            _tokenDecoder = tokenDecoder;
            _signInManager = signInManager;
            _cookieSessionManager = cookieSessionManager;
            _headersSessionManager = headersSessionManager;
            _logger = logger;
            _dbContext = dbContext;
        }

        #endregion

        #region Public methods

        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> HeadersLogin(LoginViewModel model)
        {
            if (string.IsNullOrWhiteSpace(model.Password) || string.IsNullOrWhiteSpace(model.UserName))
            {
                return Unauthorized("Provide username with password");
            }

            var signInResult = default(Microsoft.AspNetCore.Identity.SignInResult);

            var adsgd = _cookieSessionManager;
            
            try
            {
                var user = await _userManager.FindByNameAsync(model.UserName);

                if (user == null)
                {
                    return Unauthorized("The user with provided name doesn't exist");
                }
                
                signInResult = await _signInManager.PasswordSignInAsync(user.UserName, model.Password, false, false);

                if (signInResult == SignInResult.Failed)
                {
                    return Unauthorized("Wrong password");
                }
                
                return Ok(await StartSessionAsync(user, model.UserName, _headersSessionManager));
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        [Authorize(Policy = PolicyConstants.BasicAccess)]
        [HttpGet]
        [Route("CheckAccess")]
        public ActionResult CheckAccess()
        {
            return Ok();
        }
        
        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register(LoginViewModel model)
        {
            var user = new AppUser(model.UserName);

            try
            {
                await _userManager.CreateAsync(user, model.Password);
                await _userManager.AddToRoleAsync(user, RolesConstants.BasicUser);
                return Accepted();
            }
            catch (Exception e)
            {
                return BadRequest("Either the user already exist or something went wrong");
            }
        }

        #endregion

        #region Private methods

        private async Task<LoggedUserViewModel> StartSessionAsync(AppUser appUser, string userName, ISessionManager sessionManager)
        {
            if (sessionManager is CookieSessionManager)
            {
                var roles = await _userManager.GetRolesAsync(appUser);
                await _cookieSessionManager.StartSessionAsync(appUser);
                return new LoggedUserViewModel
                {
                    Name = userName,
                    Roles = roles.ToArray()
                };
            }
            else
            {
                var roles = await _userManager.GetRolesAsync(appUser);
                var tokenPair = await _headersSessionManager.StartSessionAsync(appUser);
                return new HeadersLoggedUserViewModel()
                {
                    TokenPair = tokenPair,
                    Name = userName,
                    Roles = roles.ToArray()
                };
            }
        }

        #endregion
    }
}