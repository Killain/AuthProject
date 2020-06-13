using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using AuthProject.Auth.Models.Identity;
using AuthProject.Auth.Options;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthProject.Auth.Providers
{
    public class RefreshTokenProvider : IUserTwoFactorTokenProvider<AppUser>
    {
        #region Private Fields
        
        private readonly IOptions<JwtOptions> _options;
        private readonly ILogger<RefreshTokenProvider> _logger;
        private readonly SymmetricSecurityKey _securityKey;
        
        #endregion

        #region Constructor

        public RefreshTokenProvider(IOptions<JwtOptions> options, ILogger<RefreshTokenProvider> logger)
        {
            _options = options;
            _logger = logger;
            _securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(options.Value.Key));
        }

        #endregion

        #region Public Methods

        public async Task<string> GenerateAsync(string purpose, UserManager<AppUser> manager, AppUser user)
        {
            var creds = new SigningCredentials(_securityKey, SecurityAlgorithms.HmacSha256Signature);

            var refreshToken = CreateToken
            (
                creds, 
                _options.Value.Issuer, 
                _options.Value.Audience, 
                new List<Claim>(), 
                DateTime.UtcNow.AddMinutes(_options.Value.RefreshTokenLifetime)
            );

            refreshToken.SigningKey = _securityKey;
            refreshToken.Payload["UserName"] = user.UserName;

            return await Task.FromResult(new JwtSecurityTokenHandler().WriteToken(refreshToken));
        }

        public Task<bool> ValidateAsync(string purpose, string token, UserManager<AppUser> manager, AppUser user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            if (!tokenHandler.CanReadToken(token))
            { 
                return Task.FromResult(false);
            }

            try
            {
                ValidateTokenWithParams(token);
                return Task.FromResult(true);
            }
            catch (SecurityTokenExpiredException e)
            {
                _logger.LogError($"Refresh token verification error: {e.Message}");
                throw;
            }
            catch (SecurityTokenException e)
            {
                _logger.LogError($"Refresh token verification error: {e.Message}");
                return Task.FromResult(false);
            }
        }

        public Task<bool> CanGenerateTwoFactorTokenAsync(UserManager<AppUser> manager, AppUser user)
        {
            return Task.FromResult(true);
        }

        #endregion
        
        #region Private Methods

        private JwtSecurityToken CreateToken(SigningCredentials credentials, string issuer, string audience, IEnumerable<Claim> claims, DateTime expires)
        {
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();

            return handler.CreateJwtSecurityToken(
                issuer: issuer,
                audience: audience,
                subject: new ClaimsIdentity(claims),
                notBefore: DateTime.UtcNow,
                expires: expires,
                signingCredentials: credentials
            );
        }
        
        private SecurityToken ValidateTokenWithParams(string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            tokenHandler.ValidateToken(token,
                new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    IssuerSigningKey = _securityKey,
                    ValidIssuer = _options.Value.Issuer,
                    ValidAudience = _options.Value.Audience,
                    ClockSkew = TimeSpan.FromSeconds(5)
                }, 
                out SecurityToken validatedToken);

            return validatedToken;
        }
        
        #endregion
    }
}