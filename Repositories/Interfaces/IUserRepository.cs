using DTOs.UserDTOs.Response;
using Repositories.Helpers;

namespace Repositories.Interfaces
{
    public interface IUserRepository
    {
        Task<PagedList<UserDetailsDTO>> GetUserDetailsAsync(int pageNumber, int pageSize);
    }
}
