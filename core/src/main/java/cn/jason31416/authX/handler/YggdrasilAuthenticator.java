package cn.jason31416.authX.handler;

import cn.jason31416.authX.message.Message;
import cn.jason31416.authx.api.AbstractAuthenticator;
import cn.jason31416.authX.util.Config;
import cn.jason31416.authX.util.Logger;
import cn.jason31416.authX.util.MapTree;
import cn.jason31416.authX.util.PlayerProfile;
import com.google.gson.Gson;
import lombok.SneakyThrows;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

public class YggdrasilAuthenticator {
    public static CompletableFuture<Boolean> checkExists(String username, UUID uuid, String url){
        CompletableFuture<Boolean> future = new CompletableFuture<>();
        var res = HttpClient.newHttpClient().sendAsync(HttpRequest.newBuilder()
                .uri(URI.create(url+"session/minecraft/profile/"+uuid.toString().replace("-", "")))
                .GET()
                .build(), HttpResponse.BodyHandlers.ofString());
        res.thenAccept(response -> {
            if(response.statusCode() == 200) {
                var ret = new Gson().fromJson(response.body(), PlayerProfile.class);
//                Logger.info("User detected as "+url);
                future.complete(username.equals(ret.name));
            }else{
                future.complete(false);
            }
        });
        return future;
    }

    @SneakyThrows
    public static boolean checkAllExists(String username, UUID uuid){
        List<CompletableFuture<Boolean> > futures = new ArrayList<>();
        for (String method : Config.getSection("authentication.yggdrasil.auth-servers").getKeys()) {
            String url = Config.getString("authentication.yggdrasil.auth-servers."+method);
            futures.add(checkExists(username, uuid, url));
        }
        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                .completeOnTimeout(null, 10, TimeUnit.SECONDS)
                .join();
        for (CompletableFuture<Boolean> future : futures) {
            if(future.get()){
                return true;
            }
        }
        return false;
    }

    public static CompletableFuture<PlayerProfile> authenticateVia(String username, String authMethod, String url){
        CompletableFuture<PlayerProfile> future = new CompletableFuture<>();
        var res = HttpClient.newHttpClient().sendAsync(HttpRequest.newBuilder()
                .uri(URI.create(url))
                .GET()
                .build(), HttpResponse.BodyHandlers.ofString());
        res.thenAccept(response -> {
            if(response.statusCode() == 200) {
                var ret = new Gson().fromJson(response.body(), PlayerProfile.class);
                ret.authentication = authMethod;
                future.complete(ret);
            }else{
                future.complete(null);
            }
        });
        return future;
    }

    private static boolean isLocalPasswordBackend() {
        String backend = Config.getString("authentication.password.method").toLowerCase();
        return backend.equals("sqlite") || backend.equals("mysql") || backend.equals("h2");
    }

    private static PlayerProfile applyAuthPolicy(String username, PlayerProfile profile) {
        String authMethod = profile.authentication;
        LoginSession session = LoginSession.getSession(username);
        DatabaseHandler db = DatabaseHandler.getInstance();

        if (!isLocalPasswordBackend()) {
            db.setPreferred(username, authMethod);
            session.setAuthMethod(authMethod);
            if (!db.getAuthMethods(username).contains(authMethod)) {
                session.setVerifyPassword(true);
                session.setPasswordIntroMessage(Message.getMessage("auth.yggdrasil-new-need-verification").add("auth_method", authMethod));
            }
            return profile;
        }

        AbstractAuthenticator.UserStatus status = AbstractAuthenticator.getInstance().fetchStatus(username);
        List<String> verifiedMethods = db.getAuthMethods(username);
        boolean methodVerified = verifiedMethods.contains(authMethod);

        if (status == AbstractAuthenticator.UserStatus.NOT_EXIST) {
            db.ensureImportedUser(username);
            db.setPreferred(username, authMethod);
            db.ensureAuthMethod(username, authMethod);
            session.setAuthMethod(authMethod);
            if (Config.getConfigTree().getBoolean("authentication.auto-set-uuid-on-register", true)) {
                db.setUUID(username, session.getUuid());
            }
            session.setVerifyPassword(false);
            return profile;
        }

        // Backward-compat for existing imported users: bootstrap first verified method once
        // so they are not locked out before having a chance to set a password.
        if (status == AbstractAuthenticator.UserStatus.IMPORTED && verifiedMethods.isEmpty() && !db.hasPassword(username)) {
            db.setPreferred(username, authMethod);
            db.ensureAuthMethod(username, authMethod);
            session.setAuthMethod(authMethod);
            session.setVerifyPassword(false);
            return profile;
        }

        if (!methodVerified && !db.hasPassword(username)) {
            session.setDisconnectMessage(Message.getMessage("auth.bind-requires-password"));
            return null;
        }

        db.setPreferred(username, authMethod);
        session.setAuthMethod(authMethod);

        if (!methodVerified) {
            session.setVerifyPassword(true);
            session.setPasswordIntroMessage(Message.getMessage("auth.yggdrasil-new-need-verification").add("auth_method", authMethod));
            return profile;
        }

        session.setVerifyPassword(false);
        return profile;
    }

    public static PlayerProfile authenticate(String username, String serverID, String ip) {
        System.out.println(username+" "+serverID+" "+ip);
        MapTree authServers = Config.getSection("authentication.yggdrasil.auth-servers");
        try{
            String preferredMethod = DatabaseHandler.getInstance().getPreferredMethod(username);
            if(preferredMethod!=null&&!preferredMethod.isEmpty()&&authServers.contains(preferredMethod)) {
                String url = authServers.get(preferredMethod) + "session/minecraft/hasJoined?username=" + username + "&serverId=" + serverID;
                if (Config.getBoolean("authentication.yggdrasil.verify-ip")) url += "&ip=" + ip;
                var res = authenticateVia(username, preferredMethod, url);
                if (res.get() != null) {
                    PlayerProfile accepted = applyAuthPolicy(username, res.get());
                    if (accepted != null) {
                        return accepted;
                    }
                }
            }
            var session = LoginSession.getSessionMap().get(username);
            if(!session.isEnforcePrimaryMethod()) {
                List<CompletableFuture<PlayerProfile>> futures = new ArrayList<>();
                for (String method : authServers.getKeys()) {
                    if (!method.equals(preferredMethod)) {
                        String url1 = authServers.get(method) + "session/minecraft/hasJoined?username=" + username + "&serverId=" + serverID;
                        if (Config.getBoolean("authentication.yggdrasil.verify-ip")) url1 += "&ip=" + ip;
                        futures.add(authenticateVia(username, method, url1));
                    }
                }

                CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                        .completeOnTimeout(null, 10, TimeUnit.SECONDS)
                        .join();

                for (CompletableFuture<PlayerProfile> future : futures) {
                    if (future.isDone() && future.get() != null) {
                        PlayerProfile accepted = applyAuthPolicy(username, future.get());
                        if (accepted != null) {
                            return accepted;
                        }
                    }
                }
            }
            return null;
        }catch (Exception e){
            Logger.error("Failed to authenticate " + username + ": " + e.getMessage());
        }
        return null;
    }
}
