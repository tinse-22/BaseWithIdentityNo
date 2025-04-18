using Microsoft.AspNetCore.Identity;

namespace Services.Extensions.Mapers
{
    public static class MappingExtensions
    {
        public static async Task<UserResponse> ToUserResponseAsync(this User user, UserManager<User> userManager, string? accessToken = null, string? refreshToken = null)
        {
            var roles = await userManager.GetRolesAsync(user);
            return new UserResponse
            {
                Id = user.Id,
                FirstName = user.FirstName ?? string.Empty,
                LastName = user.LastName ?? string.Empty,
                Email = user.Email ?? string.Empty,
                Gender = user.Gender ?? string.Empty,
                PhoneNumbers = user.PhoneNumber ?? string.Empty,
                CreateAt = user.CreateAt,
                UpdateAt = user.UpdateAt,
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                Roles = roles.ToList()
            };
        }

        public static CurrentUserResponse ToCurrentUserResponse(this User user, string? accessToken = null)
        {
            return new CurrentUserResponse
            {
                FirstName = user.FirstName ?? string.Empty,
                LastName = user.LastName ?? string.Empty,
                Email = user.Email ?? string.Empty,
                Gender = user.Gender ?? string.Empty,
                PhoneNumbers = user.PhoneNumber ?? string.Empty,
                CreateAt = user.CreateAt,
                UpdateAt = user.UpdateAt,
                AccessToken = accessToken
            };
        }
    }
}
