namespace DTOs.UserDTOs.Request
{
    public class EmailRequest
    {
        public required string To { get; set; }
        public required string Subject { get; set; }
        public required string Body { get; set; }
    }
}
