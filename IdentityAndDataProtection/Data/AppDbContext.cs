using IdentityAndDataProtection.Models;
using Microsoft.EntityFrameworkCore;

namespace IdentityAndDataProtection.Data
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

        public DbSet<User> Users { get; set; }
    }
}
