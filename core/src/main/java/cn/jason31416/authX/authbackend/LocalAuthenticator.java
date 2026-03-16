package cn.jason31416.authX.authbackend;

import at.favre.lib.crypto.bcrypt.BCrypt;
import cn.jason31416.authx.api.AbstractAuthenticator;
import cn.jason31416.authX.handler.DatabaseHandler;
import cn.jason31416.authX.handler.LoginSession;
import cn.jason31416.authX.util.Config;
import com.velocitypowered.api.util.UuidUtils;
import lombok.SneakyThrows;

import java.nio.charset.StandardCharsets;

public class LocalAuthenticator extends AbstractAuthenticator {
    @SneakyThrows
    public void initialize(){
        try(var conn = DatabaseHandler.getInstance().getConnection()){
            conn.prepareStatement("CREATE TABLE IF NOT EXISTS users (username VARCHAR(255) PRIMARY KEY, password VARCHAR(255) DEFAULT NULL, email VARCHAR(255) DEFAULT NULL, format VARCHAR(255), register_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
                    .execute();
        }
    }

    @SneakyThrows
    @Override
    public UserStatus fetchStatus(String username) {
        try(var conn = DatabaseHandler.getInstance().getConnection()){
            var stmt = conn.prepareStatement("SELECT * FROM users WHERE username =?");
            stmt.setString(1, username);
            var rs = stmt.executeQuery();
            if(rs.next()) {
                return rs.getString("password") == null ? UserStatus.IMPORTED : UserStatus.REGISTERED;
            }else{
                return UserStatus.NOT_EXIST;
            }
        }
    }

    @Override
    public RequestResult requestRegister(String username, String email) {
        throw new UnsupportedOperationException();
    }

    @Override
    public RequestResult verifyEmail(String username, String email, String password, String code) {
        throw new UnsupportedOperationException();
    }

    @SneakyThrows
    @Override
    public RequestResult forceRegister(String username, String password) {
        if(fetchStatus(username)!= UserStatus.NOT_EXIST) return RequestResult.USER_ALREADY_EXISTS;
        try(var conn = DatabaseHandler.getInstance().getConnection()){
            var stmt = conn.prepareStatement("INSERT INTO users (username, password, format, email) VALUES (?,?,?,?)");
            stmt.setString(1, username);
            stmt.setString(2, BCrypt.withDefaults().hashToString(10, password.toCharArray()));
            stmt.setString(3, "bcrypt");
            stmt.setString(4, null);
            stmt.execute();

            if (Config.getConfigTree().getBoolean("authentication.auto-set-uuid-on-register", true)) {
                var session = LoginSession.getSessionMap().get(username);
                var uuid = session == null ? UuidUtils.generateOfflinePlayerUuid(username) : session.getUuid();
                DatabaseHandler.getInstance().setUUID(username, uuid);
            }

            return RequestResult.SUCCESS;
        }
    }

    @SneakyThrows
    @Override
    public RequestResult authenticate(String username, String password) {
        try(var conn = DatabaseHandler.getInstance().getConnection()){
            var stmt = conn.prepareStatement("SELECT * FROM users WHERE username =?");
            stmt.setString(1, username);
            var rs = stmt.executeQuery();
            if(rs.next()) {
                if(rs.getString("password") == null) {
                    return RequestResult.INVALID_PASSWORD;
                }else{
                    if(BCrypt.verifyer().verify(password.getBytes(StandardCharsets.UTF_8), rs.getString("password").getBytes(StandardCharsets.UTF_8)).verified) {
                        if(rs.getString("email") == null) return RequestResult.EMAIL_NOT_LINKED;
                        return RequestResult.SUCCESS;
                    }else{
                        return RequestResult.INVALID_PASSWORD;
                    }
                }
            }else{
                return RequestResult.USER_DOESNT_EXIST;
            }
        }
    }

    @SneakyThrows
    @Override
    public RequestResult unregister(String username) {
        if(fetchStatus(username) == UserStatus.NOT_EXIST) return RequestResult.USER_DOESNT_EXIST;
        try(var conn = DatabaseHandler.getInstance().getConnection()){
            var stmt = conn.prepareStatement("DELETE FROM users WHERE username =?;");
            stmt.setString(1, username);
            stmt.execute();
            return RequestResult.SUCCESS;
        }
    }

    @SneakyThrows
    @Override
    public RequestResult changePassword(String username, String newPassword) {
        if(fetchStatus(username) == UserStatus.NOT_EXIST) return RequestResult.USER_DOESNT_EXIST;
        try(var conn = DatabaseHandler.getInstance().getConnection()){
            var stmt = conn.prepareStatement("UPDATE users SET password = ? WHERE username =?");
            stmt.setString(1, BCrypt.withDefaults().hashToString(10, newPassword.toCharArray()));
            stmt.setString(2, username);
            stmt.execute();
            return RequestResult.SUCCESS;
        }
    }
}
