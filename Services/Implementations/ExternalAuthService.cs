using System.Security.Claims;
using Google.Apis.Auth;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Configuration;

public class ExternalAuthService : IExternalAuthService
{
    private readonly SignInManager<User> _signInManager;
    private readonly IUserService _userService;
    private readonly UserManager<User> _userManager;
    private readonly ITokenService _tokenService;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly JwtSettings _jwtSettings;
    private readonly IConfiguration _configuration;

    public ExternalAuthService(
        SignInManager<User> signInManager,
        IUserService userService,
        UserManager<User> userManager,
        ITokenService tokenService,
        IHttpContextAccessor httpContextAccessor,
        IOptions<JwtSettings> jwtOptions,
        IConfiguration configuration)
    {
        _signInManager = signInManager;
        _userService = userService;
        _userManager = userManager;
        _tokenService = tokenService;
        _httpContextAccessor = httpContextAccessor;
        _jwtSettings = jwtOptions.Value;
        _configuration = configuration;
    }
    public async Task<ApiResult<UserResponse>> ProcessGoogleTokenAsync(string tokenId)
    {
        try
        {
            Console.WriteLine($"Using Client ID: {_configuration["Authentication:Google:ClientId"]}");

            // Validate Google token with correct settings
            //ID Token bạn đang dán lên Swagger là của OAuth Playground, không phải do Web Client của bạn cấp.
            var validationSettings = new GoogleJsonWebSignature.ValidationSettings
            {
                Audience = new[] {
                    _configuration["Authentication:Google:ClientId"],           // web client của bạn
                    "407408718192.apps.googleusercontent.com"                  // client-id của OAuth Playground
                }
            };

            var payload = await GoogleJsonWebSignature.ValidateAsync(tokenId, validationSettings);

            Console.WriteLine($"Token audience: {payload.Audience}");

            // Continue with user creation/login after successful validation
            var googleInfo = new GoogleUserInfo
            {
                Email = payload.Email,
                FirstName = payload.GivenName,
                LastName = payload.FamilyName
            };

            // Example logic for creating or updating the user
            var userResp = await _userService.CreateOrUpdateGoogleUserAsync(googleInfo);
            if (userResp == null)
                return ApiResult<UserResponse>.Failure("Cannot create or update Google user");

            var user = await _userManager.FindByEmailAsync(payload.Email);
            if (user == null)
                return ApiResult<UserResponse>.Failure("User not found after creation");

            // Generate tokens
            var tokenResult = await _tokenService.GenerateToken(user);
            if (!tokenResult.IsSuccess)
                return ApiResult<UserResponse>.Failure("Cannot generate token");

            var accessToken = tokenResult.Data;
            var refreshToken = _tokenService.GenerateRefreshToken();

            // Set HttpOnly cookie for refresh token
            var cookieOpts = new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenDays)
            };
            _httpContextAccessor.HttpContext!
                .Response.Cookies.Append("refreshToken", refreshToken, cookieOpts);

            // Return user response with access token
            var dto = await user.ToUserResponseAsync(_userManager, accessToken);
            return ApiResult<UserResponse>.Success(dto);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Google authentication error: {ex.Message}");
            if (ex is InvalidJwtException jwtEx)
            {
                Console.WriteLine($"JWT Error details: {jwtEx.Message}");
            }
            return ApiResult<UserResponse>.Failure($"Google authentication failed: {ex.Message}");
        }
    }

    public async Task<ApiResult<UserResponse>> ProcessGoogleLoginAsync()
    {
        // 1) Lấy thông tin Google login
        var info = await _signInManager.GetExternalLoginInfoAsync();
        if (info == null)
            return ApiResult<UserResponse>.Failure("Google login information not found");

        // 2) Thử đăng nhập nếu đã liên kết
        var signInResult = await _signInManager.ExternalLoginSignInAsync(
            info.LoginProvider, info.ProviderKey,
            isPersistent: false, bypassTwoFactor: true);
        if (!signInResult.Succeeded)
        {
            // 3) Tạo hoặc cập nhật User
            var email = info.Principal.FindFirstValue(ClaimTypes.Email);
            var given = info.Principal.FindFirstValue(ClaimTypes.GivenName);
            var family = info.Principal.FindFirstValue(ClaimTypes.Surname);

            var googleInfo = new GoogleUserInfo
            {
                Email = email,
                FirstName = given,
                LastName = family
            };
            var userResp = await _userService.CreateOrUpdateGoogleUserAsync(googleInfo);
            if (userResp == null)
                return ApiResult<UserResponse>.Failure("Cannot create or update Google user");

            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
                return ApiResult<UserResponse>.Failure("User not found after creation");

            // 4) Xác nhận email
            if (!user.EmailConfirmed)
            {
                user.EmailConfirmed = true;
                await _userManager.UpdateAsync(user);
            }

            // 5) Link Google login
            await _userManager.AddLoginAsync(user, info);     // :contentReference[oaicite:6]{index=6}

            // 6) Sign-in cookie
            await _signInManager.SignInAsync(user, isPersistent: false);

            // 7) Sinh access + refresh token
            var tokenResult = await _tokenService.GenerateToken(user);
            if (!tokenResult.IsSuccess)
                return ApiResult<UserResponse>.Failure("Cannot generate token");
            var accessToken = tokenResult.Data;
            var refreshToken = _tokenService.GenerateRefreshToken();

            // 8) Đặt HttpOnly cookie cho refresh token
            var cookieOpts = new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenDays) 
            };
            _httpContextAccessor.HttpContext!
                .Response.Cookies.Append("refreshToken", refreshToken, cookieOpts);


            // 9) Trả về chỉ Access Token và user info
            var dto = await user.ToUserResponseAsync(
                          _userManager,
                          accessToken);            // chỉ truyền accessToken
            return ApiResult<UserResponse>.Success(dto);
        }

        // 10) Nếu đã liên kết: tương tự
        var existingUser = await _userManager.FindByLoginAsync(
                                  info.LoginProvider, info.ProviderKey);
        var existingToken = await _tokenService.GenerateToken(existingUser);
        var existingAccess = existingToken.Data;
        var newRefresh = _tokenService.GenerateRefreshToken();

        // Cập nhật cookie
        var opts = new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Expires = DateTime.UtcNow
                       .AddDays(_jwtSettings.RefreshTokenDays)
        };
        _httpContextAccessor.HttpContext!
            .Response.Cookies.Append("refreshToken",
                                     newRefresh,
                                     opts);

        var existingDto = await existingUser.ToUserResponseAsync(
                              _userManager, existingAccess);
        return ApiResult<UserResponse>.Success(existingDto);

    }

}
