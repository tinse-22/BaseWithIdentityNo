using Microsoft.AspNetCore.Builder;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WebAPI.Extensions
{
    public static class PipelineConfigurationExtensions
    {
        public static IApplicationBuilder UseApplicationPipeline(this IApplicationBuilder app)
        {
            // 1. Chuẩn bị một scope để resolve các scoped service
            var scopeFactory = app.ApplicationServices.GetRequiredService<IServiceScopeFactory>();
            using (var scope = scopeFactory.CreateScope())
            {
                var env = scope.ServiceProvider.GetRequiredService<IWebHostEnvironment>();
                var logger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();
                var db = scope.ServiceProvider.GetRequiredService<BaseIdentityDbContext>();

                try
                {
                    db.Database.Migrate();
                    // nếu cần: await DBInitializer.Initialize(db);
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Error when migrating/seeding DB.");
                }

                // Chỉ bật swagger trong dev
                if (env.IsDevelopment())
                {
                    app.UseSwagger();
                    app.UseSwaggerUI();
                }
            }

            // 2. Các middleware chung (outside the scope)
            app.UseHttpsRedirection();
            app.UseRouting();
            app.UseCors("CorsPolicy");
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseEndpoints(endpoints => endpoints.MapControllers());

            return app;
        }
    }
}
