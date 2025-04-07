using Microsoft.EntityFrameworkCore;

namespace WebAPI.DependencyInjection
{
    public static class MigrationExtensions
    {
        public static void ApplyMigrations(this IApplicationBuilder app, ILogger logger)
        {
            try
            {
                using var scope = app.ApplicationServices.CreateScope();
                var dbContext = scope.ServiceProvider.GetRequiredService<BaseIdentityDbContext>();
                dbContext.Database.Migrate();
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred while applying migrations!");
            }
        }
    }
}
