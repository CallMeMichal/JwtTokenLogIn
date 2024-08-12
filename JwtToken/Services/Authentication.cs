using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtToken.Services
{
    public class Authentication
    {
        private static IConfiguration _configuration;

        // Metoda do inicjalizacji statycznego pola _configuration
        public static void Initialize(IConfiguration configuration)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        }

        public static string GenerateJWTAuthentication(string userName, string role)
        {
            var claims = new List<Claim>
            {
                new Claim(JwtHeaderParameterNames.Jku, userName),
                new Claim(JwtHeaderParameterNames.Kid, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.NameIdentifier, userName),
                new Claim(ClaimTypes.Role, role)
            };

            var key = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(_configuration["config:JwtKey"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var expires = DateTime.Now.AddDays(Convert.ToDouble(_configuration["config:JwtExpireDays"]));

            var token = new JwtSecurityToken(
                _configuration["config:JwtIssuer"],
                _configuration["config:JwtAudience"],
                claims,
                expires: expires,
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public static List<string> ValidateToken(string token)
        {
            List<string> claims = new List<string>();
            if (token == null)
                return null;

            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_configuration["config:JwtKey"]);
            try
            {
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);

                var jwtToken = (JwtSecurityToken)validatedToken;
                var jku = jwtToken.Claims.First(claim => claim.Type == "jku").Value;
                var userName = jwtToken.Claims.First(claim => claim.Type == "kid").Value;
                var userRole = jwtToken.Claims.First(claim => claim.Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/role").Value;

                claims.Add(userRole);
                claims.Add(userName);

                return claims;
            }
            catch
            {
                return null;
            }
        }
    }
}