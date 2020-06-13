namespace AuthProject.Auth.Options
{
    public class JwtOptions
    {
        public string Key { get; set; }
        public string Issuer { get; set; }
        public string Audience { get; set; }
        public int AccessTokenLifetime { get; set; }
        public int RefreshTokenLifetime { get; set; }
    }
}