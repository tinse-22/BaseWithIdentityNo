using Microsoft.EntityFrameworkCore;
using System.Linq.Expressions;

namespace Repositories.WorkSeeds
{
    public class GenericRepository<TEntity, TKey> : IGenericRepository<TEntity, TKey> where TEntity : class
    {
        protected readonly DbContext _context;
        protected readonly DbSet<TEntity> _dbSet;

        public GenericRepository(DbContext context)
        {
            _context = context;
            _dbSet = _context.Set<TEntity>();
        }

        public async Task<TEntity> AddAsync(TEntity entity)
        {
            await _dbSet.AddAsync(entity);
            await _context.SaveChangesAsync();
            return entity;
        }

        public async Task AddRangeAsync(IEnumerable<TEntity> entities)
        {
            await _dbSet.AddRangeAsync(entities);
            await _context.SaveChangesAsync();
        }

        public async Task<IReadOnlyList<TEntity>> GetAllAsync(
            Expression<Func<TEntity, bool>>? predicate = null,
            params Expression<Func<TEntity, object>>[] includes)
        {
            IQueryable<TEntity> query = _dbSet;

            if (predicate != null)
                query = query.Where(predicate);

            if (includes != null && includes.Any())
            {
                foreach (var include in includes)
                {
                    query = query.Include(include);
                }
            }

            return await query.ToListAsync();
        }

        public async Task<TEntity?> GetByIdAsync(TKey id, params Expression<Func<TEntity, object>>[] includes)
        {
            // Nếu không có include nào thì dùng FindAsync cho hiệu năng tốt hơn
            if (includes == null || includes.Length == 0)
            {
                return await _dbSet.FindAsync(id);
            }

            // Nếu có include, xây dựng query kèm include
            IQueryable<TEntity> query = _dbSet;
            foreach (var include in includes)
            {
                query = query.Include(include);
            }

            // Lấy thông tin metadata để tìm khóa chính của entity
            var key = _context.Model.FindEntityType(typeof(TEntity))?.FindPrimaryKey();
            if (key == null || key.Properties.Count != 1)
                throw new InvalidOperationException("Entity không có khóa chính duy nhất được hỗ trợ.");

            var keyProperty = key.Properties.First();

            // Xây dựng biểu thức: entity => EF.Property<object>(entity, keyName) == id
            var parameter = Expression.Parameter(typeof(TEntity), "entity");
            var propertyAccess = Expression.Property(parameter, keyProperty.Name);
            var equals = Expression.Equal(propertyAccess, Expression.Constant(id));
            var lambda = Expression.Lambda<Func<TEntity, bool>>(equals, parameter);

            return await query.FirstOrDefaultAsync(lambda);
        }

        public async Task UpdateAsync(TEntity entity)
        {
            _dbSet.Update(entity);
            await _context.SaveChangesAsync();
        }

        public async Task UpdateRangeAsync(IEnumerable<TEntity> entities)
        {
            _dbSet.UpdateRange(entities);
            await _context.SaveChangesAsync();
        }

        public async Task DeleteAsync(TEntity entity)
        {
            _dbSet.Remove(entity);
            await _context.SaveChangesAsync();
        }

        public async Task DeleteRangeAsync(IEnumerable<TEntity> entities)
        {
            _dbSet.RemoveRange(entities);
            await _context.SaveChangesAsync();
        }
    }
}
