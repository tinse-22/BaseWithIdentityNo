namespace Repositories.WorkSeeds.Interfaces
{
    public interface IUnitOfWork
    {
        // Thêm các repository khác nếu cần

        /// <summary>
        /// Commit các thay đổi trên toàn bộ các repository.
        /// </summary>
        Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
         public IUserRepository userRepository { get; }
    }
}
