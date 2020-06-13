using AuthProject.Auth.Models.TokenPairs;

namespace AuthProject.Auth.Managers.Token
{
    public interface ITokenDecoder
    {
        DecodedTokenPair DecodeTokenPair(EncodedTokenPair encodedTokenPair);
    }
}