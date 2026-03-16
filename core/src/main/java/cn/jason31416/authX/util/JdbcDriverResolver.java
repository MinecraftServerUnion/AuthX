package cn.jason31416.authX.util;

import cn.jason31416.authX.AuthXPlugin;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URL;
import java.net.URLClassLoader;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.DriverPropertyInfo;
import java.sql.SQLException;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

public class JdbcDriverResolver {
    public enum DriverKind {
        MYSQL(
                "com.mysql",
                "mysql-connector-j",
                "8.4.0",
                "com.mysql.cj.jdbc.Driver"
        ),
        SQLITE(
                "org.xerial",
                "sqlite-jdbc",
                "3.50.3.0",
                "org.sqlite.JDBC"
        ),
        H2(
                "com.h2database",
                "h2",
                "2.3.232",
                "org.h2.Driver"
        );

        public final String group;
        public final String artifact;
        public final String version;
        public final String className;

        DriverKind(String group, String artifact, String version, String className) {
            this.group = group;
            this.artifact = artifact;
            this.version = version;
            this.className = className;
        }
    }

    private static final Map<DriverKind, Object> LOCKS = new ConcurrentHashMap<>();
    private static final Map<DriverKind, Boolean> LOADED = new ConcurrentHashMap<>();

    private static Object lock(DriverKind kind) {
        return LOCKS.computeIfAbsent(kind, k -> new Object());
    }

    public static void ensureDriver(DriverKind kind) {
        synchronized (lock(kind)) {
            if (Boolean.TRUE.equals(LOADED.get(kind))) {
                return;
            }

            try {
                Class.forName(kind.className);
                LOADED.put(kind, true);
                return;
            } catch (ClassNotFoundException ignored) {
                // try downloading driver jar
            }

            Path driverJar = downloadDriverIfNeeded(kind);
            try {
                URLClassLoader loader = new URLClassLoader(new URL[]{driverJar.toUri().toURL()}, JdbcDriverResolver.class.getClassLoader());
                Class<?> clazz = Class.forName(kind.className, true, loader);
                Driver raw = (Driver) clazz.getDeclaredConstructor().newInstance();
                DriverManager.registerDriver(new DriverShim(raw));
                cn.jason31416.authX.util.Logger.info("[driver] Loaded JDBC driver " + kind.name() + " (" + kind.className + ") from " + driverJar);
                LOADED.put(kind, true);
            } catch (Exception e) {
                throw new RuntimeException("Failed to load JDBC driver " + kind.className + " from " + driverJar + ": " + e.getMessage(), e);
            }
        }
    }

    private static Path downloadDriverIfNeeded(DriverKind kind) {
        try {
            Path dir = AuthXPlugin.getInstance().getDataDirectory().toPath().resolve("drivers");
            Files.createDirectories(dir);
            String fileName = kind.artifact + "-" + kind.version + ".jar";
            Path target = dir.resolve(fileName);
            if (Files.exists(target) && Files.size(target) > 0) {
                cn.jason31416.authX.util.Logger.info("[driver] Using cached JDBC driver " + kind.name() + " at " + target);
                return target;
            }

            String repo = Config.getConfigTree().getString("driver.maven-source", "https://repo1.maven.org/maven2/");
            if (repo == null || repo.isEmpty()) {
                repo = "https://repo1.maven.org/maven2/";
            }
            if (!repo.endsWith("/")) {
                repo += "/";
            }

            String path = kind.group.replace('.', '/') + "/" + kind.artifact + "/" + kind.version + "/" + fileName;
            String downloadUrl = repo + path;
            cn.jason31416.authX.util.Logger.info("[driver] Downloading JDBC driver " + kind.name() + " from " + downloadUrl);

            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(downloadUrl))
                    .GET()
                    .build();
            HttpResponse<InputStream> response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
            if (response.statusCode() != 200) {
                throw new RuntimeException("HTTP " + response.statusCode() + " when downloading " + downloadUrl);
            }
            try (InputStream in = response.body(); OutputStream out = Files.newOutputStream(target)) {
                in.transferTo(out);
            }
            cn.jason31416.authX.util.Logger.info("[driver] Downloaded JDBC driver " + kind.name() + " to " + target);
            return target;
        } catch (Exception e) {
            cn.jason31416.authX.util.Logger.error("[driver] Failed to download JDBC driver " + kind.name() + ": " + e.getMessage());
            throw new RuntimeException("Failed to download JDBC driver for " + kind.name()
                    + ". Check network and driver.maven-source. Reason: " + e.getMessage(), e);
        }
    }

    // Adapter to avoid classloader mismatch when registering dynamically loaded drivers.
    private static final class DriverShim implements Driver {
        private final Driver delegate;

        private DriverShim(Driver delegate) {
            this.delegate = Objects.requireNonNull(delegate);
        }

        @Override
        public java.sql.Connection connect(String url, Properties info) throws SQLException {
            return delegate.connect(url, info);
        }

        @Override
        public boolean acceptsURL(String url) throws SQLException {
            return delegate.acceptsURL(url);
        }

        @Override
        public DriverPropertyInfo[] getPropertyInfo(String url, Properties info) throws SQLException {
            return delegate.getPropertyInfo(url, info);
        }

        @Override
        public int getMajorVersion() {
            return delegate.getMajorVersion();
        }

        @Override
        public int getMinorVersion() {
            return delegate.getMinorVersion();
        }

        @Override
        public boolean jdbcCompliant() {
            return delegate.jdbcCompliant();
        }

        @Override
        public Logger getParentLogger() throws java.sql.SQLFeatureNotSupportedException {
            return delegate.getParentLogger();
        }
    }
}
