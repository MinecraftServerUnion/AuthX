package cn.jason31416.authX.handler;

import cn.jason31416.authX.AuthXPlugin;
import cn.jason31416.authX.util.Config;
import cn.jason31416.authX.util.JdbcDriverResolver;
import cn.jason31416.authx.api.IDatabaseHandler;
import com.velocitypowered.api.util.UuidUtils;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import lombok.Getter;
import lombok.SneakyThrows;

import javax.annotation.Nullable;
import java.io.File;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.UUID;

public class DatabaseHandler implements IDatabaseHandler {
    @Getter
    private static final DatabaseHandler instance=new DatabaseHandler();

    private enum DatabaseType {
        SQLITE,
        MYSQL,
        H2
    }

    private DatabaseType databaseType = DatabaseType.H2;

    public HikariDataSource dataSource;

    @Override
    public Connection getConnection() throws SQLException {
        return dataSource.getConnection();
    }

    @SneakyThrows
    public void init() {
        if(dataSource!= null&&!dataSource.isClosed()) dataSource.close();

        var method = Config.getString("authentication.password.method").toLowerCase(Locale.ROOT);
        databaseType = switch (method) {
            case "mysql" -> DatabaseType.MYSQL;
            case "sqlite" -> DatabaseType.SQLITE;
            case "h2" -> DatabaseType.H2;
            default -> throw new IllegalArgumentException("Unsupported authentication.password.method: " + method);
        };
        dataSource = new HikariDataSource(buildDataSourceConfig(databaseType));

        try (Connection connection = getConnection()) {
            connection.prepareStatement("CREATE TABLE IF NOT EXISTS authmethods (username VARCHAR(255) PRIMARY KEY, verified VARCHAR(255), preferred VARCHAR(255), modkey VARCHAR(255) default NULL)").execute();
            connection.prepareStatement("CREATE TABLE IF NOT EXISTS uuiddata (username VARCHAR(255) PRIMARY KEY, uuid VARCHAR(255))").execute();
            connection.prepareStatement("CREATE TABLE IF NOT EXISTS passwordbackup (username VARCHAR(255) PRIMARY KEY, password VARCHAR(255), pubkeyhash VARCHAR(10))").execute();
        }
    }

    private HikariConfig buildDataSourceConfig(DatabaseType databaseType) {
        HikariConfig config = new HikariConfig();
        switch (databaseType) {
            case MYSQL -> {
                JdbcDriverResolver.ensureDriver(JdbcDriverResolver.DriverKind.MYSQL);
                String host = Config.getString("authentication.password.mysql.host");
                int port = Config.getInt("authentication.password.mysql.port");
                String database = Config.getString("authentication.password.mysql.database");
                String username = Config.getString("authentication.password.mysql.username");
                String password = Config.getString("authentication.password.mysql.password");
                String parameters = Config.getString("authentication.password.mysql.parameters");

                StringBuilder url = new StringBuilder("jdbc:mysql://")
                        .append(host.isEmpty() ? "localhost" : host)
                        .append(":")
                        .append(port <= 0 ? 3306 : port)
                        .append("/")
                        .append(database.isEmpty() ? "authx" : database);
                if (!parameters.isEmpty()) {
                    url.append("?").append(parameters);
                }
                config.setJdbcUrl(url.toString());
                config.setUsername(username);
                config.setPassword(password);
            }
            case SQLITE -> {
                JdbcDriverResolver.ensureDriver(JdbcDriverResolver.DriverKind.SQLITE);
                config.setJdbcUrl("jdbc:sqlite:" + new File(AuthXPlugin.getInstance().getDataDirectory(), "usermeta.db").getAbsolutePath());
            }
            case H2 -> {
                JdbcDriverResolver.ensureDriver(JdbcDriverResolver.DriverKind.H2);
                String path = new File(AuthXPlugin.getInstance().getDataDirectory(), "usermeta").getAbsolutePath();
                String parameters = "TRACE_LEVEL_FILE=0;TRACE_LEVEL_SYSTEM_OUT=0";
                String jdbcUrl = "jdbc:h2:" + path + ";" + parameters;
                config.setJdbcUrl(jdbcUrl);
                config.setUsername("sa");
                config.setPassword("");
            }
        }
        return config;
    }

    @SneakyThrows
    @Override
    public void setUUID(String username, UUID uuid){
        try (Connection connection = getConnection()) {
            String sql = switch (databaseType) {
                case MYSQL -> "INSERT INTO uuiddata (username, uuid) VALUES (?,?) ON DUPLICATE KEY UPDATE uuid = VALUES(uuid)";
                case SQLITE -> "INSERT OR REPLACE INTO uuiddata (username, uuid) VALUES (?,?)";
                case H2 -> "MERGE INTO uuiddata (username, uuid) KEY(username) VALUES (?,?)";
            };
            var st = connection.prepareStatement(sql);
            st.setString(1, username);
            st.setString(2, uuid.toString());
            st.execute();
        }
    }
    @SneakyThrows
    @Override
    public UUID getUUID(String username) {
        try (Connection connection = getConnection()) {
            var st = connection.prepareStatement("SELECT uuid FROM uuiddata WHERE username =?");
            st.setString(1, username);
            var rs = st.executeQuery();
            if (rs.next()) {
                return UUID.fromString(rs.getString("uuid"));
            } else {
                return UuidUtils.generateOfflinePlayerUuid(username);
            }
        }
    }

    @SneakyThrows
    public boolean hasUUIDData(String username) {
        try (Connection connection = getConnection()) {
            var st = connection.prepareStatement("SELECT 1 FROM uuiddata WHERE username =? LIMIT 1");
            st.setString(1, username);
            var rs = st.executeQuery();
            return rs.next();
        }
    }

    @SneakyThrows
    public void setModKey(String username, String modkey){
        try (Connection connection = getConnection()) {
            var st = connection.prepareStatement("UPDATE authmethods SET modkey =? WHERE username =?");
            st.setString(1, modkey);
            st.setString(2, username);
            st.execute();
        }
    }
    @SneakyThrows @Nullable
    public String getModKey(String username) {
        try (Connection connection = getConnection()) {
            var st = connection.prepareStatement("SELECT modkey FROM authmethods WHERE username =?");
            st.setString(1, username);
            var rs = st.executeQuery();
            if (rs.next()) {
                return rs.getString("modkey");
            } else {
                return null;
            }
        }
    }

    @SneakyThrows
    @Override
    public void setPreferred(String username, String method){
        try (Connection connection = getConnection()) {
            switch (databaseType) {
                case MYSQL -> {
                    var st = connection.prepareStatement("INSERT INTO authmethods (username, verified, preferred) VALUES (?,?,?) ON DUPLICATE KEY UPDATE preferred = VALUES(preferred)");
                    st.setString(1, username);
                    st.setString(2, "");
                    st.setString(3, method);
                    st.execute();
                }
                case SQLITE -> {
                    // if user does not exist, create it
                    var st = connection.prepareStatement("INSERT OR IGNORE INTO authmethods (username, verified, preferred) VALUES (?,?,?)");
                    st.setString(1, username);
                    st.setString(2, "");
                    st.setString(3, method);
                    st.execute();

                    // update preferred method
                    st = connection.prepareStatement("UPDATE authmethods SET preferred =? WHERE username =?");
                    st.setString(1, method);
                    st.setString(2, username);
                    st.execute();
                }
                case H2 -> {
                    var st = connection.prepareStatement("MERGE INTO authmethods (username, verified, preferred) KEY(username) VALUES (?,?,?)");
                    st.setString(1, username);
                    st.setString(2, "");
                    st.setString(3, method);
                    st.execute();
                }
            }
        }
    }

    @SneakyThrows
    @Override
    public void addAuthMethod(String username, String method) { // it is assumed that user is already created
        try (Connection connection = getConnection()) {
            String sql = switch (databaseType) {
                case MYSQL -> "UPDATE authmethods SET verified = CONCAT(COALESCE(verified, ''), ?) WHERE username =?";
                case SQLITE -> "UPDATE authmethods SET verified = COALESCE(verified, '') || ? WHERE username =?";
                case H2 -> "UPDATE authmethods SET verified = COALESCE(verified, '') || ? WHERE username =?";
            };
            var st = connection.prepareStatement(sql);
            st.setString(1, "," + method);
            st.setString(2, username);
            st.execute();
        }
    }

    @SneakyThrows
    public void ensureImportedUser(String username) {
        try (Connection connection = getConnection()) {
            String sql = switch (databaseType) {
                case MYSQL -> "INSERT IGNORE INTO users (username, password, email, format) VALUES (?, NULL, NULL, ?)";
                case SQLITE -> "INSERT OR IGNORE INTO users (username, password, email, format) VALUES (?, NULL, NULL, ?)";
                case H2 -> "MERGE INTO users (username, password, email, format) KEY(username) VALUES (?, NULL, NULL, ?)";
            };
            var st = connection.prepareStatement(sql);
            st.setString(1, username);
            st.setString(2, "none");
            st.execute();
        }
    }

    @SneakyThrows
    public boolean hasPassword(String username) {
        try (Connection connection = getConnection()) {
            var st = connection.prepareStatement("SELECT password FROM users WHERE username =?");
            st.setString(1, username);
            var rs = st.executeQuery();
            if (!rs.next()) {
                return false;
            }
            return rs.getString("password") != null;
        }
    }

    @SneakyThrows
    public void ensureAuthMethod(String username, String method) {
        try (Connection connection = getConnection()) {
            String ensureRowSql = switch (databaseType) {
                case MYSQL -> "INSERT IGNORE INTO authmethods (username, verified, preferred) VALUES (?, '', NULL)";
                case SQLITE -> "INSERT OR IGNORE INTO authmethods (username, verified, preferred) VALUES (?, '', NULL)";
                case H2 -> "MERGE INTO authmethods (username, verified, preferred) KEY(username) VALUES (?, '', NULL)";
            };
            var ensureStmt = connection.prepareStatement(ensureRowSql);
            ensureStmt.setString(1, username);
            ensureStmt.execute();
        }

        if (!getAuthMethods(username).contains(method)) {
            addAuthMethod(username, method);
        }
    }

    @SneakyThrows
    @Override
    public List<String> getAuthMethods(String username) {
        try (Connection connection = getConnection()) {
            var st = connection.prepareStatement("SELECT verified FROM authmethods WHERE username =?");
            st.setString(1, username);
            var rs = st.executeQuery();
            if (rs.next()) {
                var verified = rs.getString("verified");
                if (verified == null || verified.isEmpty()) {
                    return List.of();
                } else {
                    return List.of(verified.substring(1).split(","));
                }
            } else {
                return List.of();
            }
        }
    }
    @SneakyThrows
    @Override
    public String getPreferredMethod(String username) {
        try (Connection connection = getConnection()) {
            var st = connection.prepareStatement("SELECT preferred FROM authmethods WHERE username =?");
            st.setString(1, username);
            var rs = st.executeQuery();
            if (rs.next()) {
                return Objects.toString(rs.getString("preferred"), "");
            } else {
                return "";
            }
        }
    }
}
