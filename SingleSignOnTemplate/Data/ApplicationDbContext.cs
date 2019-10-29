using System.Threading;
using System.Threading.Tasks;
using IdentityServer4.EntityFramework.Entities;
using IdentityServer4.EntityFramework.Extensions;
using IdentityServer4.EntityFramework.Interfaces;
using IdentityServer4.EntityFramework.Options;
using IdentityServer4.EntityFramework.Stores;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace SingleSignOnTemplate.Data
{
    public class ApplicationDbContext : IdentityDbContext, IConfigurationDbContext, IPersistedGrantDbContext
    {
        private readonly ConfigurationStoreOptions _configurationStoreOptions;
        private readonly OperationalStoreOptions _persistedGrantStoreOptions;

        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options, ConfigurationStoreOptions configurationStoreOptions, OperationalStoreOptions persistedGrantStoreOptions)
            : base(options)
        {
            _configurationStoreOptions = configurationStoreOptions;
            _persistedGrantStoreOptions = persistedGrantStoreOptions;
        }
        
        public DbSet<Client> Clients { get; set; }
        public DbSet<IdentityResource> IdentityResources { get; set; }
        public DbSet<ApiResource> ApiResources { get; set; }
        public DbSet<PersistedGrant> PersistedGrants { get; set; }
        public DbSet<DeviceFlowCodes> DeviceFlowCodes { get; set; }

        Task<int> IPersistedGrantDbContext.SaveChangesAsync()
            => SaveChangesAsync();

        Task<int> IConfigurationDbContext.SaveChangesAsync()
            => SaveChangesAsync();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.ConfigureClientContext(_configurationStoreOptions);
            modelBuilder.ConfigureResourcesContext(_configurationStoreOptions);

            modelBuilder.ConfigurePersistedGrantContext(_persistedGrantStoreOptions);
        }
    }
}
