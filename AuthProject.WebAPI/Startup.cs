using AuthProject.Auth.AuthHandlers.CookieBased;
using AuthProject.Auth.AuthHandlers.CookieBased.Handler;
using AuthProject.Auth.AuthHandlers.HeadersBased;
using AuthProject.Auth.IdentityDBContext;
using AuthProject.Auth.Managers.Session.Implementations.CookieSession;
using AuthProject.Auth.Managers.Session.Implementations.HeadersSession;
using AuthProject.Auth.Managers.Session.Stores.Cookie;
using AuthProject.Auth.Managers.Session.Stores.Headers;
using AuthProject.Auth.Managers.Token;
using AuthProject.Auth.Models.Identity;
using AuthProject.Auth.Options;
using AuthProject.Auth.Providers;
using AuthProject.WebAPI.AuthSchemes;
using AuthProject.WebAPI.Policy;
using AuthProject.WebAPI.Seeders;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace AuthProject.WebAPI
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();
            services.AddHttpContextAccessor();
            
            services.AddCors();

            services
                .AddAuthentication()
                .AddScheme<CookieAuthOptions, CookieAuthHandler>(AuthSchemesConstants.CookieAuth, null)
                .AddScheme<JwtAuthOptions, HeadersAuthHandler>(AuthSchemesConstants.JwtAuth, null);
            
            services.AddAuthorization(PolicyBuilder.BuildPolicies);
            
            #region Options
            
            services.Configure<JwtOptions>(Configuration.GetSection("Jwt"));

            #endregion

            #region Transient
            
            services.AddTransient<ITokenDecoder, TokenDecoder>();
            services.AddTransient<AccessTokenProvider>();
            services.AddTransient<RefreshTokenProvider>();
            
            #endregion
            
            #region Scoped
            
            services.AddScoped<ICookieSessionManager, CookieSessionManager>();
            services.AddScoped<IHeadersSessionManager, HeadersSessionManager>();
            
            #endregion
            
            #region Singletons
            
            services.AddSingleton<ICookieSessionStore, CookieSessionStore>();
            services.AddSingleton<IHeadersSessionStore, HeadersSessionStore>();
            
            #endregion
            
            services.AddDbContext<UsersDbContext>(options =>
                {
                    options.UseNpgsql(Configuration.GetConnectionString("IdentityDBConnection"),
                        x => x.MigrationsAssembly("AuthProject.Auth"));
                }
            );

            services
                .AddIdentity<AppUser, IdentityRole>(options =>
                {
                    options.Password.RequireNonAlphanumeric = false;
                    options.Password.RequireDigit = false;
                    options.Password.RequireLowercase = false;
                    options.Password.RequireUppercase = false;
                    options.User.AllowedUserNameCharacters =
                        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@._/-";
                    options.SignIn.RequireConfirmedEmail = false;
                    options.SignIn.RequireConfirmedPhoneNumber = false;
                    options.SignIn.RequireConfirmedAccount = false;
                    options.SignIn.RequireConfirmedPhoneNumber = false;
                })
                .AddEntityFrameworkStores<UsersDbContext>()
                .AddTokenProvider<AccessTokenProvider>(ProviderConstants.AccessTokenProvider)
                .AddTokenProvider<RefreshTokenProvider>(ProviderConstants.RefreshTokenProvider);
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            
            using (var scope = app.ApplicationServices.GetRequiredService<IServiceScopeFactory>().CreateScope())
            {
                scope.ServiceProvider.GetService<UsersDbContext>().Database.Migrate();
                RolesSeeder.Initialize(scope.ServiceProvider).Wait();
            }

            app.UseHttpsRedirection();

            app.UseAuthentication();
            app.UseRouting();
            app.UseAuthorization();

            app.UseEndpoints(endpoints => { endpoints.MapControllers(); });
        }
    }
}