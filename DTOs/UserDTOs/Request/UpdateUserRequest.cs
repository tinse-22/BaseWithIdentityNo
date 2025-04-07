using BusinessObjects.Common;

namespace DTOs.UserDTOs.Request
{
    public class UpdateUserRequest
    {
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public GenderEnums Gender { get; set; }
    }
}
