using AuthProject.Auth.Policy;
using AuthProject.WebAPI.Role;
using Microsoft.AspNetCore.Authorization;

namespace AuthProject.WebAPI.Policy
{
    public class PolicyBuilder
    {
        public static void BuildPolicies(AuthorizationOptions options)
        {
            options.AddPolicy(PolicyConstants.BasicAccess,
                policy =>
                {
                    policy.AuthenticationSchemes.Insert(0, "JwtAuth");
                    policy.AuthenticationSchemes.Insert(1, "CookieAuth");
                    policy.RequireAuthenticatedUser();
                    policy.RequireRole(RolesConstants.BasicUser);
                    policy.Build();
                }
            );
        }
    }
}