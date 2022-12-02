namespace Project.Dtos.Users
{
    public class Response
    {
        public int StatusCode { get; set; }
        public IEnumerable<string>? Errors { get; set; }
        public string? AccessToken { get; set; }
        public string? RefreshToken { get; set; }
        public DateTime? Expiration { get; set; }
    }
}

