// RepositoryServiceCollectionExtensions.cs
using BaseIdentity.Application.Services;
using Services.Implements;
using Services.Interfaces;

namespace WebAPI.DependencyInjection
{
    public static class RepositoryServiceCollectionExtensions
    {
        public static IServiceCollection AddRepositoryServices(this IServiceCollection services)
        {
            services.AddScoped<IUnitOfWork, UnitOfWork>();
            services.AddScoped(typeof(IGenericRepository<,>), typeof(GenericRepository<,>));
            services.AddScoped<ICurrentUserService, CurrentUserService>();
            services.AddScoped<IExternalAuthService, ExternalAuthService>();
            services.AddScoped<ITokenService, TokenService>();
            services.AddScoped<IUserService, UserService>();
            return services;
        }
    }
}
