using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace Services.Helpers.Mapers
{
    public static class UserMappings
    {
        // Request to Domain mappings
        public static User ToDomainUser(this UserRegisterRequest req)
        {
            return new User
            {
                FirstName = req.FirstName,
                LastName = req.LastName,
                Email = req.Email,
                Gender = req.Gender.ToString(),
                CreateAt = DateTime.UtcNow,
                UpdateAt = DateTime.UtcNow
            };
        }

        public static User ToDomainUser(this AdminCreateUserRequest req)
        {
            return new User
            {
                FirstName = req.FirstName,
                LastName = req.LastName,
                Email = req.Email,
                Gender = req.Gender?.ToString(),
                CreateAt = DateTime.UtcNow,
                UpdateAt = DateTime.UtcNow
            };
        }

        public static User ToDomainUser(this GoogleUserInfo info)
        {
            return new User
            {
                UserName = info.Email,
                FirstName = info.FirstName,
                LastName = info.LastName,
                Email = info.Email,
                CreateAt = DateTime.UtcNow,
                UpdateAt = DateTime.UtcNow
            };
        }

        public static void ApplyUpdate(this UpdateUserRequest req, User user)
        {
            if (!string.IsNullOrEmpty(req.FirstName)) user.FirstName = req.FirstName;
            if (!string.IsNullOrEmpty(req.LastName)) user.LastName = req.LastName;
            if (new EmailAddressAttribute().IsValid(req.Email)) user.Email = req.Email;
            if (!string.IsNullOrEmpty(req.PhoneNumbers)) user.PhoneNumber = req.PhoneNumbers;
            if (req.Gender != null) user.Gender = req.Gender.ToString();
            user.UpdateAt = DateTime.UtcNow;
        }

        public static bool MergeGoogleInfo(this GoogleUserInfo info, User user)
        {
            bool changed = false;
            if (user.FirstName != info.FirstName)
            {
                user.FirstName = info.FirstName;
                changed = true;
            }
            if (user.LastName != info.LastName)
            {
                user.LastName = info.LastName;
                changed = true;
            }
            if (changed)
            {
                user.UpdateAt = DateTime.UtcNow;
            }
            return changed;
        }

        // Domain to Response mappings
        public static async Task<UserResponse> ToUserResponseAsync(this User user, UserManager<User> userManager, string accessToken = null, string refreshToken = null)
        {
            var roles = await userManager.GetRolesAsync(user);
            return new UserResponse
            {
                Id = user.Id,
                FirstName = user.FirstName,
                LastName = user.LastName,
                Email = user.Email,
                Gender = user.Gender,
                PhoneNumbers = user.PhoneNumber,
                CreateAt = user.CreateAt,
                UpdateAt = user.UpdateAt,
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                Roles = roles.ToList()
            };
        }

        public static CurrentUserResponse ToCurrentUserResponse(this User user, string accessToken = null)
        {
            return new CurrentUserResponse
            {
                FirstName = user.FirstName,
                LastName = user.LastName,
                Email = user.Email,
                Gender = user.Gender,
                PhoneNumbers = user.PhoneNumber,
                CreateAt = user.CreateAt,
                UpdateAt = user.UpdateAt,
                AccessToken = accessToken
            };
        }
    }
}