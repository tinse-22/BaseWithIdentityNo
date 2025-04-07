using System.Security.Claims;
using Microsoft.AspNetCore.Identity;

namespace BaseIdentity.Application.Services
{
    public class ExternalAuthService : IExternalAuthService
    {
        private readonly SignInManager<User> _signInManager;
        private readonly UserManager<User> _userManager;
        private readonly ITokenService _tokenService;

        public ExternalAuthService(
            SignInManager<User> signInManager,
            UserManager<User> userManager,
            ITokenService tokenService)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _tokenService = tokenService;
        }

        public async Task<ApiResult<string>> ProcessGoogleLoginAsync()
        {
            // Retrieve external login info from Google
            var info = await _signInManager.GetExternalLoginInfoAsync().ConfigureAwait(false);
            if (info == null)
            {
                return ApiResult<string>.Failure("Unable to retrieve external login info from Google.");
            }

            // Attempt to sign in with the external login
            var signInResult = await _signInManager
                .ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false)
                .ConfigureAwait(false);

            User user;
            if (!signInResult.Succeeded)
            {
                // Retrieve email from external login info
                var email = info.Principal.FindFirstValue(ClaimTypes.Email);
                if (string.IsNullOrEmpty(email))
                {
                    return ApiResult<string>.Failure("Email not present in Google account.");
                }

                // Check if the user already exists
                user = await _userManager.FindByEmailAsync(email).ConfigureAwait(false);
                if (user == null)
                {
                    // Create a new user if it does not exist
                    user = new User
                    {
                        UserName = email,
                        Email = email
                    };

                    var createResult = await _userManager.CreateAsync(user).ConfigureAwait(false);
                    if (!createResult.Succeeded)
                    {
                        var errorMsg = string.Join(", ", createResult.Errors.Select(e => e.Description));
                        return ApiResult<string>.Failure(errorMsg);
                    }
                }

                // Associate the external login with the user
                var addLoginResult = await _userManager.AddLoginAsync(user, info).ConfigureAwait(false);
                if (!addLoginResult.Succeeded)
                {
                    var errorMsg = string.Join(", ", addLoginResult.Errors.Select(e => e.Description));
                    return ApiResult<string>.Failure(errorMsg);
                }

                // Sign in the user
                await _signInManager.SignInAsync(user, isPersistent: false).ConfigureAwait(false);
            }
            else
            {
                // If external sign in succeeded, get the linked user
                user = await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey).ConfigureAwait(false);
                if (user == null)
                {
                    return ApiResult<string>.Failure("No user associated with the provided Google login.");
                }
            }

            // Generate a JWT token for the user
            var tokenResult = await _tokenService.GenerateToken(user).ConfigureAwait(false);
            return tokenResult;
        }
    }

}
