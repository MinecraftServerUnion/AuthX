package cn.jason31416.authX.handler;

import cn.jason31416.authX.message.Message;
import cn.jason31416.authX.util.Logger;
import com.velocitypowered.api.util.UuidUtils;
import lombok.Getter;
import lombok.Setter;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Getter
public class LoginSession implements cn.jason31416.authx.api.ILoginSession {
    @Getter
    private static Map<String, LoginSession> sessionMap = new HashMap<>();

    private String username;
    private UUID uuid;

    @Setter
    private boolean enforcePrimaryMethod = false;
    @Setter
    private boolean verifyPassword = true;
    @Setter
    private String authMethod = null;

    @Setter
    private String password = null;

    @Setter
    private Message passwordIntroMessage = null;

    @Setter
    private Message disconnectMessage = null;

    public LoginSession(String username, UUID uuid) {
        this.username = username;
        this.uuid = uuid;
    }

    public static LoginSession getSession(String username) {
        if(!sessionMap.containsKey(username)){
            Logger.error("Unknown session found for username: "+username+"! Things might break.");
            return new LoginSession(username, UuidUtils.generateOfflinePlayerUuid(username));
        }
        return sessionMap.get(username);
    }
}
