using System.Data;
using Bower.Abstractions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace Bower.Persistence;

public sealed class EfSourceCursorStore : ISourceCursorStore
{
    private readonly DbContextOptions<SourceCursorDbContext> options;
    private readonly string databasePath;

    public EfSourceCursorStore(string databasePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);

        this.databasePath = Path.GetFullPath(databasePath);
        string? directory = Path.GetDirectoryName(this.databasePath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        SqliteConnectionStringBuilder connection = new()
        {
            DataSource = this.databasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
            Pooling = true,
            DefaultTimeout = 5
        };

        options = new DbContextOptionsBuilder<SourceCursorDbContext>()
            .UseSqlite(connection.ToString())
            .Options;
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await using SourceCursorDbContext context = new(options);
        await context.Database.EnsureCreatedAsync(cancellationToken);
        ApplyRestrictivePermissions();
    }

    public Task<SourceCursorSnapshot?> ReadAsync(
        string sourceId,
        CancellationToken cancellationToken = default)
    {
        return new Store(options).ReadAsync(sourceId, cancellationToken);
    }

    public Task<bool> TryAdvanceAsync(
        string sourceId,
        long expectedVersion,
        string value,
        DateTimeOffset updatedAt,
        CancellationToken cancellationToken = default)
    {
        return new Store(options).TryAdvanceAsync(
            sourceId,
            expectedVersion,
            value,
            updatedAt,
            cancellationToken);
    }

    private void ApplyRestrictivePermissions()
    {
        if (OperatingSystem.IsWindows() || !File.Exists(databasePath))
        {
            return;
        }

        File.SetUnixFileMode(databasePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    private sealed class Store(DbContextOptions<SourceCursorDbContext> options)
        : ISourceCursorStore
    {
        public async Task<SourceCursorSnapshot?> ReadAsync(
            string sourceId,
            CancellationToken cancellationToken = default)
        {
            ValidateSourceId(sourceId);
            await using SourceCursorDbContext context = new(options);
            SourceCursorEntity? entity = await context.SourceCursors
                .AsNoTracking()
                .SingleOrDefaultAsync(item => item.SourceId == sourceId, cancellationToken);
            return entity is null
                ? null
                : new SourceCursorSnapshot(entity.Value, entity.Version);
        }

        public async Task<bool> TryAdvanceAsync(
            string sourceId,
            long expectedVersion,
            string value,
            DateTimeOffset updatedAt,
            CancellationToken cancellationToken = default)
        {
            ValidateSourceId(sourceId);
            ArgumentException.ThrowIfNullOrWhiteSpace(value);
            ArgumentOutOfRangeException.ThrowIfNegative(expectedVersion);

            await using SourceCursorDbContext context = new(options);
            await using var transaction = await context.Database.BeginTransactionAsync(
                IsolationLevel.Serializable,
                cancellationToken);

            SourceCursorEntity? entity = await context.SourceCursors
                .SingleOrDefaultAsync(item => item.SourceId == sourceId, cancellationToken);

            if (entity is null)
            {
                if (expectedVersion != 0)
                {
                    return false;
                }

                context.SourceCursors.Add(
                    new SourceCursorEntity
                    {
                        SourceId = sourceId,
                        Value = value,
                        Version = 1,
                        UpdatedAt = updatedAt.ToUniversalTime()
                    });
            }
            else
            {
                if (entity.Version != expectedVersion)
                {
                    return false;
                }

                entity.Value = value;
                entity.Version++;
                entity.UpdatedAt = updatedAt.ToUniversalTime();
            }

            try
            {
                await context.SaveChangesAsync(cancellationToken);
                await transaction.CommitAsync(cancellationToken);
                return true;
            }
            catch (DbUpdateException)
            {
                return false;
            }
        }

        private static void ValidateSourceId(string sourceId)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(sourceId);
            if (sourceId.Length > 128)
            {
                throw new ArgumentException(
                    "Source identifier cannot exceed 128 characters.",
                    nameof(sourceId));
            }
        }
    }
}

internal sealed class SourceCursorDbContext(DbContextOptions<SourceCursorDbContext> options)
    : DbContext(options)
{
    public DbSet<SourceCursorEntity> SourceCursors => Set<SourceCursorEntity>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<SourceCursorEntity>(
            entity =>
            {
                entity.ToTable("source_cursors");
                entity.HasKey(item => item.SourceId);
                entity.Property(item => item.SourceId).HasMaxLength(128);
                entity.Property(item => item.Value).IsRequired();
                entity.Property(item => item.Version).IsConcurrencyToken();
                entity.Property(item => item.UpdatedAt).IsRequired();
            });
    }
}

internal sealed class SourceCursorEntity
{
    public required string SourceId { get; init; }

    public required string Value { get; set; }

    public long Version { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }
}
