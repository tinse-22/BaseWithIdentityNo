using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace Services.Implements
{
    public class TokenService : ITokenService
    {
        private static readonly JwtSecurityTokenHandler _tokenHandler = new();
        private readonly SymmetricSecurityKey _secretKey;
        private readonly string? _validIssuer;
        private readonly string? _validAudience;
        readonly double _expires;
        private readonly UserManager<User> _userManager;

        public TokenService(IConfiguration configuration, UserManager<User> userManager)
        {
            _userManager = userManager;
            var jwtSettings = configuration.GetSection("JwtSettings").Get<JwtSettings>()
                ?? throw new InvalidOperationException("JWT settings are not configured.");

            if (string.IsNullOrEmpty(jwtSettings.Key))
                throw new InvalidOperationException("JWT secret key is not configured.");

            _secretKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.Key));
            _validIssuer = jwtSettings.ValidIssuer;
            _validAudience = jwtSettings.ValidAudience;
            _expires = jwtSettings.Expires;
        }

        public string GenerateRefreshToken()
        {
            var randomNumber = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        private async Task<List<Claim>> GetClaimsAsync(User user)
        {
            // Assuming the user is not null as it's been checked before calling this method.
            var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName ?? string.Empty),
                    new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                    new Claim(ClaimTypes.Email, user.Email ?? string.Empty),
                    new Claim("FirstName", user.FirstName ?? string.Empty),
                    new Claim("LastName", user.LastName ?? string.Empty),
                    new Claim("Gender", user.Gender ?? string.Empty)
                };

            var roles = await _userManager.GetRolesAsync(user).ConfigureAwait(false);
            claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

            return claims;
        }

        private JwtSecurityToken GenerateTokenOptions(SigningCredentials signingCredentials, List<Claim> claims)
        {
            return new JwtSecurityToken(
                issuer: _validIssuer,
                audience: _validAudience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(_expires),
                signingCredentials: signingCredentials
            );
        }

        public async Task<ApiResult<string>> GenerateToken(User user)
        {
            if (user == null)
                return ApiResult<string>.Failure("User is null.");

            var signingCredentials = new SigningCredentials(_secretKey, SecurityAlgorithms.HmacSha256);
            var claims = await GetClaimsAsync(user).ConfigureAwait(false);
            var tokenOptions = GenerateTokenOptions(signingCredentials, claims);
            var token = _tokenHandler.WriteToken(tokenOptions);

            return ApiResult<string>.Success(token);
        }
    }
}
