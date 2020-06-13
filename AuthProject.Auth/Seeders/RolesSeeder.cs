using System;
using System.Threading.Tasks;
using AuthProject.WebAPI.Role;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore.Internal;
using Microsoft.Extensions.DependencyInjection;

namespace AuthProject.WebAPI.Seeders
{
    public class RolesSeeder
    {
         public static async Task Initialize(IServiceProvider serviceProvider)
        {
            var roleManager = serviceProvider.GetService<RoleManager<IdentityRole>>();
            if (roleManager.Roles.Any())
            {
                return;
            }
            
            await roleManager.CreateAsync(new IdentityRole(RolesConstants.BasicUser));
        }
    }
}