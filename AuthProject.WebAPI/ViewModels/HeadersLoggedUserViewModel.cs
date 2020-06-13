using AuthProject.Auth.Models.TokenPairs;

namespace AuthProject.WebAPI.ViewModels
{
    public class HeadersLoggedUserViewModel : LoggedUserViewModel
    {
        public EncodedTokenPair TokenPair { get; set; }
    }
}