using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace Services.Extensions.Mapers
{
    public static class UserRequestMappings
    {
        public static User ToDomainUser(this UserRegisterRequest req) => new User
        {
            FirstName = req.FirstName,
            LastName = req.LastName,
            Email = req.Email,
            Gender = req.Gender.ToString(),
            CreateAt = DateTime.UtcNow,
            UpdateAt = DateTime.UtcNow
        };

        public static User ToDomainUser(this AdminCreateUserRequest req) => new User
        {
            FirstName = req.FirstName,
            LastName = req.LastName,
            Email = req.Email,
            Gender = req.Gender?.ToString(),
            CreateAt = DateTime.UtcNow,
            UpdateAt = DateTime.UtcNow
        };

        public static User ToDomainUser(this GoogleUserInfo info) => new User
        {
            UserName = info.Email,
            FirstName = info.FirstName,
            LastName = info.LastName,
            Email = info.Email,
            CreateAt = DateTime.UtcNow,
            UpdateAt = DateTime.UtcNow
        };

        private static string FirstToken(string s) =>
            string.IsNullOrWhiteSpace(s)
                ? string.Empty
                : s
                    .Split(' ', StringSplitOptions.RemoveEmptyEntries)[0]
                    .Trim();

        public static string GenerateUsername(this UserRegisterRequest req)
        {
            var first = FirstToken(req.FirstName);
            var last = FirstToken(req.LastName);
            return (first + last).ToLowerInvariant();
        }

        public static string GenerateUsername(this AdminCreateUserRequest req)
        {
            var first = FirstToken(req.FirstName);
            var last = FirstToken(req.LastName);
            return (first + last).ToLowerInvariant();
        }

        public static bool MergeGoogleInfo(this GoogleUserInfo info, User user)
        {
            var changed = false;
            if (user.FirstName != info.FirstName) { user.FirstName = info.FirstName; changed = true; }
            if (user.LastName != info.LastName) { user.LastName = info.LastName; changed = true; }
            return changed;
        }

        public static void ApplyToDomain(this UpdateUserRequest req, User user)
        {
            if (!string.IsNullOrEmpty(req.FirstName)) user.FirstName = req.FirstName;
            if (!string.IsNullOrEmpty(req.LastName)) user.LastName = req.LastName;
            if (new EmailAddressAttribute().IsValid(req.Email)) user.Email = req.Email;
            if (!string.IsNullOrEmpty(req.PhoneNumbers)) user.PhoneNumber = req.PhoneNumbers;
            if (req.Gender != null) user.Gender = req.Gender.ToString();
        }

        public static Task<UserResponse> BuildResponseAsync( this User user, UserManager<User> mgr,  string token = null, string refresh = null)
            => user.ToUserResponseAsync(mgr, token, refresh);

        public static CurrentUserResponse BuildCurrentResponse(this User user, string token)
            => user.ToCurrentUserResponse(token);
    }
}
