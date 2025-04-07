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
        /// Lấy danh sách user kèm role dạng phân trang.
        /// </summary>
        public async Task<PagedList<UserDetailsDTO>> GetUserDetailsAsync(int pageNumber, int pageSize)
        {
            // Sử dụng GroupJoin để lấy các role của từng user trong 1 truy vấn duy nhất
            var groupedQuery = _context.Users
                .GroupJoin(
                    _context.Set<IdentityUserRole<Guid>>(),
                    u => u.Id,
                    ur => ur.UserId,
                    (u, urGroup) => new { User = u, UserRoles = urGroup }
                )
                .Select(x => new
                {
                    x.User,
                    RoleNames = x.UserRoles
                        .Join(
                            _context.Roles,
                            ur => ur.RoleId,
                            r => r.Id,
                            (ur, r) => r.Name
                        ).ToList()
                })
                .OrderByDescending(x => x.User.CreateAt);

            // Lấy tổng số bản ghi
            var count = await groupedQuery.CountAsync();

            // Lấy dữ liệu theo phân trang
            var data = await groupedQuery
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            // Ánh xạ dữ liệu sang UserDetailsDTO 
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
