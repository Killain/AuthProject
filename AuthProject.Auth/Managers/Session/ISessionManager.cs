using System.Threading.Tasks;
using AuthProject.Auth.Models.Identity;
using AuthProject.Auth.Models.TokenPairs;

namespace AuthProject.Auth.Managers.Session
{
    public interface ISessionManager
    {
        Task<EncodedTokenPair> StartSessionAsync(AppUser user);
        Task EndSessionAsync(string userName);
        Task<EncodedTokenPair> UpdateSessionAsync(AppUser user);
        Task<bool> IsTokenPairInUse(EncodedTokenPair tokenPair);
        Task<bool> IsAppUserInSession(string userName);
    }
}