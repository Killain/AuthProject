using System.IdentityModel.Tokens.Jwt;
using AuthProject.Auth.Models.TokenPairs;

namespace AuthProject.Auth.Managers.Token
{
    public class TokenDecoder : ITokenDecoder
    {
        #region Private fields
        private JwtSecurityTokenHandler _handler;

        #endregion

        #region Constructor
        public TokenDecoder()
        {
            _handler = new JwtSecurityTokenHandler();
        }
        #endregion

        #region Public methods
        
        public DecodedTokenPair DecodeTokenPair(EncodedTokenPair encodedTokenPair)
        {
            return new DecodedTokenPair
            {
                AccessToken = _handler.ReadJwtToken(encodedTokenPair.AccessToken),
                RefreshToken = _handler.ReadJwtToken(encodedTokenPair.RefreshToken)
            };
        }
        
        #endregion
    }
}