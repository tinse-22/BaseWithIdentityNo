namespace Repositories.Commons
{
    public record ApiResult<T>
    {
        public bool IsSuccess { get; set; }
        public T? Data { get; set; }
        public string? Message { get; set; }
        public static ApiResult<T> Succeed(T? data, string message)
        {
            return new ApiResult<T> { IsSuccess = true, Data = data, Message = message };
        }

        public static ApiResult<T> Error(T? data, string Message)
        {
            return new ApiResult<T> { IsSuccess = false, Data = data, Message = Message };
        }

        public static ApiResult<T> Fail(Exception ex)
        {
            return new ApiResult<T>
            {
                IsSuccess = false,
                Data = default,
                Message = ex.Message
            };
        }
    }
}
