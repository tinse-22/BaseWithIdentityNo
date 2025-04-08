using Microsoft.EntityFrameworkCore;
namespace WebAPI.DependencyInjection
{
    public static class InfrastructureServiceCollectionExtensions
    {
        public static IServiceCollection AddInfrastructureServices(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddDbContext<BaseIdentityDbContext>(options =>
                options.UseSqlServer(
                    configuration.GetConnectionString("IdentityAuthentication"),
                    sqlOptions => sqlOptions.MigrationsAssembly("Repositories") // Chỉ rõ tên assembly của tầng Repositories
                ));

            services.AddCors(options =>
            {
                options.AddPolicy("CorsPolicy", builder =>
                {
                    builder.AllowAnyOrigin()
                           .AllowAnyMethod()
                           .AllowAnyHeader();
                });
            });

            return services;
        }
    }
}
