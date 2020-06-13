using AuthProject.Auth.Models.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AuthProject.Auth.IdentityDBContext
{
    public class UsersDbContext : IdentityDbContext<AppUser>
    {
        public UsersDbContext(DbContextOptions<UsersDbContext> options)
            : base(options)
        {
            
        }
    }
}