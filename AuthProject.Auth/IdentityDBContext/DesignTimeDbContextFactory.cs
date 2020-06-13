using System.IO;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;

namespace AuthProject.Auth.IdentityDBContext
{
    public class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<UsersDbContext>
    {
        public UsersDbContext CreateDbContext(string[] args)
        {
            IConfigurationRoot configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile(Directory.GetCurrentDirectory() + "/../AuthProject.WebAPI/appsettings.json")
                .Build();
            
            var builder = new DbContextOptionsBuilder<UsersDbContext>(); 
            var connectionString = configuration.GetConnectionString("IdentityDBConnection"); 
            builder.UseNpgsql(connectionString); 
            return new UsersDbContext(builder.Options);
        }
    }
}