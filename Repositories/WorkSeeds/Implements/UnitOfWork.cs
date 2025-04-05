using Repositories.WorkSeeds.Interfaces;

namespace Repositories.WorkSeeds.Implements
{
    public class UnitOfWork : IUnitOfWork
    {
        private readonly BaseIdentityDbContext _context;
        private bool _disposed;

        public UnitOfWork(BaseIdentityDbContext context)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));

        }
        /// <summary>
        /// Commit các thay đổi trên toàn bộ context.
        /// </summary>
        public async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
        {
            return await _context.SaveChangesAsync(cancellationToken);
        }

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
