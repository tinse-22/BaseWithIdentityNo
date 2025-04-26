namespace DTOs.UserDTOs.Request
{
    public class EmailRequest
    {
        public List<string> To { get; set; }
        public string Subject { get; set; }
        public string Body { get; set; }
        public int RetryCount { get; set; } = 0;
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public EmailPriority Priority { get; set; } = EmailPriority.Normal;
    }
    public enum EmailPriority
    {
        High, // For 2FA, password reset, etc.
        Normal, // For regular communication
        Low // For marketing, newsletters, etc.
    }
}
