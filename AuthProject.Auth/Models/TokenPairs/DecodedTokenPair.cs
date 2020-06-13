using System.IdentityModel.Tokens.Jwt;

namespace AuthProject.Auth.Models.TokenPairs
{
    public class DecodedTokenPair
    {
        public JwtSecurityToken AccessToken { get; set; }
        public JwtSecurityToken RefreshToken { get; set; }
    }
}