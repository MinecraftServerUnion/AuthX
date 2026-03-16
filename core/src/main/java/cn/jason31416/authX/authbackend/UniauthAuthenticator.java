package cn.jason31416.authX.authbackend;

import at.favre.lib.crypto.bcrypt.BCrypt;
import cn.jason31416.authX.AuthXPlugin;
import cn.jason31416.authX.handler.UniAuthAPIClient;
import cn.jason31416.authx.api.AbstractAuthenticator;
import cn.jason31416.authX.handler.DatabaseHandler;
import cn.jason31416.authX.util.Config;
import cn.jason31416.authX.util.Logger;
import cn.jason31416.authX.util.MapTree;
import cn.jason31416.authX.util.RSAUtil;
import lombok.SneakyThrows;

import java.io.File;
import java.io.FileInputStream;

public class UniauthAuthenticator extends AbstractAuthenticator {
    @Override
    public UserStatus fetchStatus(String username) {
        var userInfo = UniAuthAPIClient.fetchUserInfo(username);
        if(!userInfo.getBoolean("profile.exists")) return UserStatus.NOT_EXIST;
        return userInfo.getBoolean("profile.registered")?UserStatus.REGISTERED:UserStatus.IMPORTED;
    }
    @SneakyThrows
    private void recordEncrypted(String username, String password){
        String publicKey = UniAuthAPIClient.fetchPublicKey(false);
        String hashed = UniAuthAPIClient.hashWithFormat(publicKey, "SHA-256").substring(0, 8);
        try(var conn = DatabaseHandler.getInstance().getConnection()){
            var st = conn.prepareStatement("REPLACE INTO passwordbackup (username, password, pubkeyhash) VALUES (?,?,?)");
            st.setString(1, username);
            st.setString(2, RSAUtil.encryptByPublicKey(BCrypt.withDefaults().hashToString(10, password.toCharArray()), publicKey));
            st.setString(3, hashed);
            st.executeUpdate();
        }
    }
    @SneakyThrows
    public static int attemptRecovery(){
        File keyFile = new File(AuthXPlugin.getInstance().getDataDirectory(), "rsa_keys.json");
        if(!keyFile.exists()) {
            throw new IllegalStateException("Missing rsa_keys.json file.");
        }
        String pubkey, privkey;
        try(FileInputStream fis = new FileInputStream(keyFile)){
            var item =  MapTree.fromJson(new String(fis.readAllBytes()));
            pubkey = item.getString("publickey");
            privkey = item.getString("privatekey");
        }
        int cnt = 0;
        String pubkeyhash = UniAuthAPIClient.hashWithFormat(pubkey, "SHA-256").substring(0, 8);

        try(var conn = DatabaseHandler.getInstance().getConnection()){
            conn.prepareStatement("CREATE TABLE IF NOT EXISTS users (username VARCHAR(255) PRIMARY KEY, password VARCHAR(255) DEFAULT NULL, email VARCHAR(255) DEFAULT NULL, format VARCHAR(255), register_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
                    .execute();

            var st = conn.prepareStatement("SELECT * FROM passwordbackup");
            var rs = st.executeQuery();

            while(rs.next()){
                var username = rs.getString("username");
                try {
                    var encryptedPassword = rs.getString("password");
                    var pubkeystored = rs.getString("pubkeyhash");
                    if(!pubkeyhash.equals(pubkeystored)){
                        Logger.warn("Skipping "+username+" due to mismatched public key hash.");
                        continue;
                    }
                    var decryptedPassword = RSAUtil.decryptByPrivateKey(encryptedPassword, privkey);
                    var stmt = conn.prepareStatement("REPLACE INTO users (username, password, format, email) VALUES (?,?,?,?)");
                    stmt.setString(1, username);
                    stmt.setString(2, decryptedPassword);
                    stmt.setString(3, "bcrypt");
                    stmt.setString(4, null);
                    stmt.execute();
                    cnt++;
                }catch (Exception e){
                    Logger.error("Failed to recover password for user "+username+": "+e.getMessage());
                }
            }
        }
        return cnt;
    }

    @Override
    public RequestResult requestRegister(String username, String email) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public RequestResult verifyEmail(String username, String email, String password, String code) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public RequestResult forceRegister(String username, String password) {
        var res = UniAuthAPIClient.registerWithoutEmail(username, password);
        if(res == UniAuthAPIClient.AuthResult.SUCCESS){
            DatabaseHandler.getInstance().setPasswordSet(username, true);
            return RequestResult.SUCCESS;
        }else if(res == UniAuthAPIClient.AuthResult.ALREADY_REGISTERED){
            return RequestResult.USER_ALREADY_EXISTS;
        }else{
            return RequestResult.UNKNOWN_ERROR;
        }
    }

    @Override
    public RequestResult authenticate(String username, String password) {
        var ret = switch(UniAuthAPIClient.login(username, password)){
            case SUCCESS -> RequestResult.SUCCESS;
            case INVALID_PASSWORD -> RequestResult.INVALID_PASSWORD;
            case NOT_REGISTERED -> RequestResult.USER_DOESNT_EXIST;
            case EMAIL_NOT_VERIFIED -> RequestResult.EMAIL_NOT_LINKED;
            default -> RequestResult.UNKNOWN_ERROR;
        };
        if(ret==RequestResult.SUCCESS||ret==RequestResult.EMAIL_NOT_LINKED){
            DatabaseHandler.getInstance().setPasswordSet(username, true);
            if(Config.getConfigTree().getBoolean("authentication.password.uniauth.perform-local-backup", true)){
                recordEncrypted(username, password);
            }
        }
        return ret;
    }

    @Override
    public RequestResult unregister(String username) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public RequestResult changePassword(String username, String newPassword) {
        var res = UniAuthAPIClient.forceResetPassword(username, newPassword);
        if(!res.isEmpty()) Logger.warn("Failed to change password for user: "+res);
        if (res.isEmpty()) {
            DatabaseHandler.getInstance().setPasswordSet(username, true);
            return RequestResult.SUCCESS;
        }
        return RequestResult.UNKNOWN_ERROR;
    }

    public RequestResult changePasswordWithOld(String username, String oldPassword, String newPassword){
        var res = UniAuthAPIClient.resetPassword(username, oldPassword, newPassword);
        if(res) {
            DatabaseHandler.getInstance().setPasswordSet(username, true);
            return RequestResult.SUCCESS;
        }
        return RequestResult.INVALID_PASSWORD;
    }
}
