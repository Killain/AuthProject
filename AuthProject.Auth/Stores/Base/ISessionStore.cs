using System.Threading.Tasks;
using AuthProject.Auth.Models.Identity;
using AuthProject.Auth.Models.TokenPairs;

namespace AuthProject.Auth.Managers.Session.Stores.Base
{
    public interface ISessionStore
    {
        Task AddAsync(AppUser user, EncodedTokenPair tokenPair);
        Task RemoveAsync(string userName);
        Task UpdateAsync(AppUser user, EncodedTokenPair tokenPair);
        Task<bool> IsTokenPairExists(EncodedTokenPair encodedTokenPair);
        Task<bool> IsAppUserInSession(string userName);
    }
}