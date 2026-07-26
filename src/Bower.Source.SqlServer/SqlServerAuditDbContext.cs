using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;

namespace Bower.Source.SqlServer;

internal sealed class SqlServerAuditDbContext : DbContext
{
    private readonly SqlServerSourceOptions sourceOptions;

    public SqlServerAuditDbContext(SqlServerSourceOptions sourceOptions)
        : base(CreateOptions(sourceOptions))
    {
        this.sourceOptions = sourceOptions;
    }

    public DbSet<SqlServerAuditRow> AuditRows => Set<SqlServerAuditRow>();

    public string MappingKey => sourceOptions.MappingKey;

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        SqlServerColumnMappings columns = sourceOptions.Columns;
        modelBuilder.Entity<SqlServerAuditRow>(
            entity =>
            {
                entity.HasNoKey();
                entity.ToTable(sourceOptions.Table, sourceOptions.Schema);
                entity.Property(row => row.Sequence).HasColumnName(columns.Sequence);
                entity.Property(row => row.EventTime).HasColumnName(columns.EventTime);
                entity.Property(row => row.Username).HasColumnName(columns.Username);
                entity.Property(row => row.Action).HasColumnName(columns.Action);
                entity.Property(row => row.TargetType).HasColumnName(columns.TargetType);
                entity.Property(row => row.TargetId).HasColumnName(columns.TargetId);
                entity.Property(row => row.PreviousValue).HasColumnName(columns.PreviousValue);
                entity.Property(row => row.NewValue).HasColumnName(columns.NewValue);
                entity.Property(row => row.SourceIpAddress).HasColumnName(columns.SourceIpAddress);
            });
    }

    private static DbContextOptions<SqlServerAuditDbContext> CreateOptions(
        SqlServerSourceOptions sourceOptions)
    {
        return new DbContextOptionsBuilder<SqlServerAuditDbContext>()
            .UseSqlServer(
                sourceOptions.ConnectionString,
                sql => sql.CommandTimeout(sourceOptions.CommandTimeoutSeconds))
            .UseQueryTrackingBehavior(QueryTrackingBehavior.NoTracking)
            .ReplaceService<IModelCacheKeyFactory, SqlServerModelCacheKeyFactory>()
            .Options;
    }
}

internal sealed class SqlServerModelCacheKeyFactory : IModelCacheKeyFactory
{
    public object Create(DbContext context, bool designTime)
    {
        return context is SqlServerAuditDbContext source
            ? (context.GetType(), source.MappingKey, designTime)
            : (object)(context.GetType(), designTime);
    }
}

internal sealed class SqlServerAuditRow
{
    public long Sequence { get; set; }

    public DateTimeOffset EventTime { get; set; }

    public string? Username { get; set; }

    public string? Action { get; set; }

    public string? TargetType { get; set; }

    public string? TargetId { get; set; }

    public string? PreviousValue { get; set; }

    public string? NewValue { get; set; }

    public string? SourceIpAddress { get; set; }
}
