using Microsoft.AspNetCore.Identity;

namespace AuthProject.Auth.Models.Identity
{
    public class AppUser: IdentityUser
    {
        public AppUser()
        {
            
        }

        public AppUser(string userName) : base(userName)
        {
            
        }
    }
}