package cn.jason31416.authX.handler;

import cn.jason31416.authX.util.Config;
import cn.jason31416.authX.util.JdbcDriverResolver;
import cn.jason31416.authX.util.Logger;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

public class MultiLoginUuidMigrator {
    private static final AtomicBoolean RUNNING = new AtomicBoolean(false);

    public record MigrationResult(int total, int imported, int skippedExisting, int skippedInvalid, int errors, long durationMs, boolean dryRun) {}

    public static boolean isRunning() {
        return RUNNING.get();
    }

    private static UUID bytesToUuid(byte[] bytes) {
        if (bytes == null || bytes.length != 16) {
            return null;
        }
        ByteBuffer bb = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN);
        return new UUID(bb.getLong(), bb.getLong());
    }

    private static Connection getSourceConnection() throws Exception {
        String backend = Config.getConfigTree().getString("migration.multilogin.backend", "MYSQL").toUpperCase(Locale.ROOT);
        return switch (backend) {
            case "MYSQL" -> {
                JdbcDriverResolver.ensureDriver(JdbcDriverResolver.DriverKind.MYSQL);
                String host = Config.getConfigTree().getString("migration.multilogin.mysql.host", "localhost");
                int port = Config.getConfigTree().getInt("migration.multilogin.mysql.port", 3306);
                String database = Config.getConfigTree().getString("migration.multilogin.mysql.database", "multilogin");
                String username = Config.getConfigTree().getString("migration.multilogin.mysql.username", "root");
                String password = Config.getConfigTree().getString("migration.multilogin.mysql.password", "");
                String parameters = Config.getConfigTree().getString("migration.multilogin.mysql.parameters", "");

                StringBuilder jdbc = new StringBuilder("jdbc:mysql://")
                        .append(host)
                        .append(":")
                        .append(port)
                        .append("/")
                        .append(database);
                if (parameters != null && !parameters.isEmpty()) {
                    jdbc.append("?").append(parameters);
                }
                yield DriverManager.getConnection(jdbc.toString(), username, password);
            }
            case "H2" -> {
                JdbcDriverResolver.ensureDriver(JdbcDriverResolver.DriverKind.H2);
                String path = Config.getConfigTree().getString("migration.multilogin.h2.path", "");
                String username = Config.getConfigTree().getString("migration.multilogin.h2.username", "sa");
                String password = Config.getConfigTree().getString("migration.multilogin.h2.password", "");
                String params = Config.getConfigTree().getString("migration.multilogin.h2.parameters", "TRACE_LEVEL_FILE=0;TRACE_LEVEL_SYSTEM_OUT=0");
                if (path == null || path.isEmpty()) {
                    throw new IllegalArgumentException("migration.multilogin.h2.path is empty.");
                }
                String jdbc = "jdbc:h2:" + path + (params == null || params.isEmpty() ? "" : ";" + params);
                yield DriverManager.getConnection(jdbc, username, password);
            }
            default -> throw new IllegalArgumentException("Unsupported migration.multilogin.backend: " + backend);
        };
    }

    public static MigrationResult migrate(boolean dryRun) {
        if (!RUNNING.compareAndSet(false, true)) {
            throw new IllegalStateException("Migration is already running.");
        }

        long start = System.currentTimeMillis();
        int total = 0, imported = 0, skippedExisting = 0, skippedInvalid = 0, errors = 0;
        boolean logProgress = Config.getConfigTree().getBoolean("migration.multilogin.log-progress", true);

        try (Connection sourceConn = getSourceConnection()) {
            String prefix = Config.getConfigTree().getString("migration.multilogin.table-prefix", "multilogin");
            String table = prefix + "_in_game_profile_v3";
            String query = "SELECT in_game_uuid, current_username_original FROM " + table;

            try (PreparedStatement st = sourceConn.prepareStatement(query);
                 ResultSet rs = st.executeQuery()) {
                while (rs.next()) {
                    total++;
                    String username = rs.getString("current_username_original");
                    UUID uuid = bytesToUuid(rs.getBytes("in_game_uuid"));

                    if (username == null || username.isBlank() || uuid == null) {
                        skippedInvalid++;
                        continue;
                    }

                    try {
                        if (DatabaseHandler.getInstance().hasUUIDData(username)) {
                            skippedExisting++;
                            continue;
                        }
                        if (!dryRun) {
                            DatabaseHandler.getInstance().setUUID(username, uuid);
                        }
                        imported++;
                    } catch (Exception e) {
                        errors++;
                        if (logProgress) {
                            Logger.warn("[migrateml] Failed to import user " + username + ": " + e.getMessage());
                        }
                    }
                }
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        } finally {
            RUNNING.set(false);
        }

        long duration = System.currentTimeMillis() - start;
        return new MigrationResult(total, imported, skippedExisting, skippedInvalid, errors, duration, dryRun);
    }
}
