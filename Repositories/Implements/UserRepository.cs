using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Repositories
{
    public class UserRepository : IUserRepository
    {
        private readonly BaseIdentityDbContext _context;

        public UserRepository(BaseIdentityDbContext context)
        {
            _context = context;
        }

        /// <summary>
        /// Retrieves a paginated list of users along with their assigned roles.
        /// </summary>
        public async Task<PagedList<UserDetailsDTO>> GetUserDetailsAsync(int pageNumber, int pageSize)
        {
            // Use AsNoTracking() to improve read performance by avoiding unnecessary change tracking
            var query = _context.Users
                .AsNoTracking()
                .OrderByDescending(u => u.CreateAt)
                .Select(u => new
                {
                    User = u,
                    RoleNames = (from ur in _context.Set<IdentityUserRole<Guid>>().AsNoTracking()
                                 join r in _context.Roles.AsNoTracking() on ur.RoleId equals r.Id
                                 where ur.UserId == u.Id
                                 select r.Name).ToList()
                });

            // Count the total number of users
            var count = await query.CountAsync();

            // Paginate the data
            var data = await query
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            // Map the result to UserDetailsDTO
            var dtos = data.Select(x => new UserDetailsDTO
            {
                Id = x.User.Id,
                FirstName = x.User.FirstName ?? string.Empty,
                LastName = x.User.LastName ?? string.Empty,
                Email = x.User.Email ?? string.Empty,
                Gender = x.User.Gender,
                CreateAt = x.User.CreateAt,
                UpdateAt = x.User.UpdateAt,
                Roles = x.RoleNames
            }).ToList();

            return new PagedList<UserDetailsDTO>(dtos, count, pageNumber, pageSize);
        }
    }
}
