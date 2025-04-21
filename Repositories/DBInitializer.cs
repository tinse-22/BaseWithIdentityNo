using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Repositories
{
    public static class DBInitializer
    {
        public static async Task Initialize(
            BaseIdentityDbContext context,
            UserManager<User> userManager)
        {
            #region Seed Roles
            if (!context.Roles.Any())
            {
                var roles = new List<Role>
                {
                    new Role { Name = "ADMIN", NormalizedName = "ADMIN" },
                    new Role { Name = "USER", NormalizedName = "USER" }
                };

                await context.AddRangeAsync(roles);
                await context.SaveChangesAsync();
            }
            #endregion

            #region Seed Users
            if (!context.Users.Any())
            {
                // Seed Admin user
                var admin = new User
                {
                    UserName = "vutrungtin",
                    Email = "trungtin2272002@gmail.com",
                    FirstName = "vutrung",
                    LastName = "tin",
                    Gender = "Male",
                    PhoneNumber = "0937213289",
                    CreateAt = DateTime.UtcNow.AddHours(7),
                    UpdateAt = DateTime.UtcNow.AddHours(7)
                };
                await CreateUserAsync(userManager, admin, "0937213289Tin@", "ADMIN");

                // Seed Staff user
                var staff = new User
                {
                    UserName = "staff",
                    Email = "staff@staff.com",
                    FirstName = "Staff",
                    LastName = "User",
                    Gender = "Female", // hoặc giá trị phù hợp
                    PhoneNumber = "0123456789",
                    CreateAt = DateTime.UtcNow.AddHours(7),
                    UpdateAt = DateTime.UtcNow.AddHours(7)
                };
                await CreateUserAsync(userManager, staff, "0937213289Tin@", "USER");    

                // Seed một số khách hàng (customers)
                var customers = new List<User>
                {
                    new User
                    {
                        UserName = "staf",
                        Email = "stafMaster@gmail.com",
                        FirstName = "Staff",
                        LastName = "Master",
                        Gender = "Male",
                        PhoneNumber = "0123456789",
                        CreateAt = DateTime.UtcNow.AddHours(7),
                        UpdateAt = DateTime.UtcNow.AddHours(7)
                    },
                    new User
                    {
                        UserName = "peter",
                        Email = "peter@fpt.edu.vn",
                        FirstName = "Peter",
                        LastName = "Hiller",
                        Gender = "Male",
                        PhoneNumber = "0123456789",
                        CreateAt = DateTime.UtcNow.AddHours(7),
                        UpdateAt = DateTime.UtcNow.AddHours(7)
                    },
                    new User
                    {
                        UserName = "kaka",
                        Email = "kaka@fpt.edu.vn",
                        FirstName = "Kaka",
                        LastName = "User",
                        Gender = "Male",
                        PhoneNumber = "0123456789",
                        CreateAt = DateTime.UtcNow.AddHours(7),
                        UpdateAt = DateTime.UtcNow.AddHours(7)
                    },
                    new User
                    {
                        UserName = "musk",
                        Email = "musk@fpt.edu.vn",
                        FirstName = "Musk",
                        LastName = "Mon",
                        Gender = "Male",
                        PhoneNumber = "0123456789",
                        CreateAt = DateTime.UtcNow.AddHours(7),
                        UpdateAt = DateTime.UtcNow.AddHours(7)
                    },
                    new User
                    {
                        UserName = "gate",
                        Email = "gate@fpt.edu.vn",
                        FirstName = "Gate",
                        LastName = "Gill",
                        Gender = "Male",
                        PhoneNumber = "0123456789",
                        CreateAt = DateTime.UtcNow.AddHours(7),
                        UpdateAt = DateTime.UtcNow.AddHours(7)
                    },
                    new User
                    {
                        UserName = "chung",
                        Email = "trunghcse181597@fpt.edu.vn",
                        FirstName = "Chung",
                        LastName = "HC",
                        Gender = "Male",
                        PhoneNumber = "0123456789",
                        CreateAt = DateTime.UtcNow.AddHours(7),
                        UpdateAt = DateTime.UtcNow.AddHours(7)
                    }
                };

                foreach (var customer in customers)
                {
                    // Bạn có thể tùy chọn gán role mặc định cho khách hàng nếu cần, ví dụ: "USER"
                    await CreateUserAsync(userManager, customer, "0937213289Tin@", "USER");
                }
            }
            #endregion

            // Cập nhật SecurityStamp cho các user nếu chưa có
            var allUsers = await context.Users.ToListAsync();
            foreach (var user in allUsers)
            {
                if (string.IsNullOrEmpty(user.SecurityStamp))
                {
                    await userManager.UpdateSecurityStampAsync(user);
                    Console.WriteLine($"Security stamp updated for user {user.UserName}");
                }
            }
        }

        private static async Task CreateUserAsync(UserManager<User> userManager, User user, string password, string role)
        {
            var userExist = await userManager.FindByEmailAsync(user.Email!);
            if (userExist == null)
            {
                var result = await userManager.CreateAsync(user, password);
                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(user, role);
                }
                else
                {
                    // Log lỗi chi tiết
                    var errorMsg = string.Join(", ", result.Errors.Select(e => e.Description));
                    Console.WriteLine($"Error creating user {user.Email}: {errorMsg}");
                }
            }
            else
            {
                Console.WriteLine($"User {user.Email} already exists.");
            }
        }
    }
}
