namespace Repositories.WorkSeeds.Implements
{
    public class UnitOfWork : IUnitOfWork
    {
        private readonly BaseIdentityDbContext _context;
        private bool _disposed;
        private readonly IUserRepository _userRepository;

        public UnitOfWork(BaseIdentityDbContext context, IUserRepository userRepository)
        {
            _context = context;
            _userRepository = userRepository;

        }
        /// <summary>
        /// Commit các thay đổi trên toàn bộ context.
        /// </summary>
        public async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
        {
            return await _context.SaveChangesAsync(cancellationToken);
        }
        public IUserRepository userRepository => _userRepository;

        #region Dispose Pattern
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _context.Dispose();
                }
                _disposed = true;
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        #endregion
    }

}
