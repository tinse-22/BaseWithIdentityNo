using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Services.Helpers;

namespace Services.Extensions
{
    public static class UserManagerExtensions
    {
        public static async Task<bool> ExistsByEmailAsync(
            this UserManager<User> mgr, string email)
            => await mgr.FindByEmailAsync(email) != null;

        public static async Task<IdentityResultWrapper> CreateUserAsync(
            this UserManager<User> mgr, User user, string password = null)
        {
            var res = password != null
                ? await mgr.CreateAsync(user, password)
                : await mgr.CreateAsync(user);
            return new IdentityResultWrapper(res);
        }

        public static Task AddDefaultRoleAsync(
            this UserManager<User> mgr, User user)
            => mgr.AddToRoleAsync(user, "USER");

        public static Task AddRolesAsync(
            this UserManager<User> mgr, User user, IEnumerable<string> roles)
            => mgr.AddToRolesAsync(user, roles ?? new[] { "USER" });

        public static Task SetRefreshTokenAsync(
            this UserManager<User> mgr, User user, string token)
            => mgr.SetAuthenticationTokenAsync(user, "MyApp", "RefreshToken", token);

        public static async Task<(bool IsValid, User User)> ValidateCredentialsAsync(
            this UserManager<User> mgr, string email, string password)
        {
            var user = await mgr.FindByEmailAsync(email);
            if (user == null) return (false, null);
            var ok = await mgr.CheckPasswordAsync(user, password);
            return (ok, ok ? user : null);
        }

        public static Task<bool> IsUserLockedOutAsync(
            this UserManager<User> mgr, User user)
            => mgr.IsLockedOutAsync(user);

        public static Task ResetAccessFailedAsync(
            this UserManager<User> mgr, User user)
            => mgr.ResetAccessFailedCountAsync(user);

        public static async Task<bool> ValidateRefreshTokenAsync(
            this UserManager<User> mgr, User user, string token)
            => await mgr.GetAuthenticationTokenAsync(user, "MyApp", "RefreshToken") == token;

        public static async Task<IdentityResultWrapper> RemoveRefreshTokenAsync(
            this UserManager<User> mgr, User user)
        {
            var res = await mgr.RemoveAuthenticationTokenAsync(
                user, "MyApp", "RefreshToken");
            return new IdentityResultWrapper(res);
        }

        public static async Task<IdentityResultWrapper> ChangeUserPasswordAsync(
            this UserManager<User> mgr, User user, string oldPwd, string newPwd)
        {
            var res = await mgr.ChangePasswordAsync(user, oldPwd, newPwd);
            return new IdentityResultWrapper(res);
        }

        public static async Task<IdentityResultWrapper> SetLockoutAsync(
            this UserManager<User> mgr, User user, bool enable, DateTimeOffset until)
        {
            await mgr.SetLockoutEnabledAsync(user, enable);
            var res = await mgr.SetLockoutEndDateAsync(user, until);
            return new IdentityResultWrapper(res);
        }

        public static Task UpdateSecurityStampAsync(
            this UserManager<User> mgr, User user)
            => mgr.UpdateSecurityStampAsync(user);

        public static async Task UpdateRolesAsync(
            this UserManager<User> mgr, User user, IEnumerable<string> roles)
        {
            var oldRoles = await mgr.GetRolesAsync(user);
            await mgr.RemoveFromRolesAsync(user, oldRoles);
            await mgr.AddToRolesAsync(user, roles ?? new[] { "USER" });
        }
    }
}
