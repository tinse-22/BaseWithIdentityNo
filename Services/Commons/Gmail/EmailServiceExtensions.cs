using Microsoft.Extensions.DependencyInjection;
using Quartz;

namespace Services.Commons.Gmail
{
    public static class EmailServiceExtensions
    {
        public static IServiceCollection AddEmailServices(this IServiceCollection services, Action<EmailSettings> configureOptions)
        {
            // Register options
            services.Configure(configureOptions);

            // Register singleton instances
            services.AddSingleton<EmailQueue>();

            // Register services
            services.AddTransient<IEmailService, EmailService>();
            services.AddTransient<IEmailQueueService, EmailQueueService>();
            services.AddTransient<SendEmailJob>();

            // Register hosted services
            services.AddHostedService<EmailBackgroundService>();
            services.AddHostedService<EmailReminderService>();

            // Add Quartz
            services.AddQuartz(q =>
            {
                
            });
            services.AddQuartzHostedService(options =>
            {
                options.WaitForJobsToComplete = true;
            });

            return services;
        }
    }
}
