package cn.jason31416.authX.handler;

import cn.jason31416.authX.AuthXPlugin;
import cn.jason31416.authx.api.AbstractAuthenticator;
import cn.jason31416.authX.hook.FloodgateHandler;
import cn.jason31416.authX.injection.ReflectionException;
import cn.jason31416.authX.message.Message;
import cn.jason31416.authX.util.Config;
import cn.jason31416.authX.util.Logger;
import com.velocitypowered.api.event.PostOrder;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.DisconnectEvent;
import com.velocitypowered.api.event.connection.PreLoginEvent;
import com.velocitypowered.api.event.player.GameProfileRequestEvent;
import com.velocitypowered.api.event.player.PlayerChatEvent;
import com.velocitypowered.api.util.GameProfile;
import com.velocitypowered.proxy.connection.MinecraftConnection;
import com.velocitypowered.proxy.connection.client.InitialInboundConnection;
import com.velocitypowered.proxy.connection.client.LoginInboundConnection;
import lombok.SneakyThrows;
import net.elytrium.limboapi.api.event.LoginLimboRegisterEvent;

import javax.annotation.Nonnull;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

public class EventListener {
    private static final MethodHandle DELEGATE_FIELD;
    private static final Set<String> pendingLogins = new HashSet<>();
    public static final Map<UUID, Long> loginPremiumFailedCache = new ConcurrentHashMap<>();

    static {
        try {
            DELEGATE_FIELD = MethodHandles.privateLookupIn(LoginInboundConnection.class, MethodHandles.lookup())
                    .findGetter(LoginInboundConnection.class, "delegate", InitialInboundConnection.class);
        } catch (Exception e) {
            throw new ReflectionException(e.getMessage(), e);
        }
    }

    private static boolean PCLUUIDFilter(UUID uuid){
        String uuidStr = uuid.toString().replace("-", "");
        return uuidStr.startsWith("0000000000") && uuidStr.charAt(12)=='3' && uuidStr.charAt(16)=='9';
    }

    public static boolean checkUserYggdrasilStatusFromUUID(String username, UUID uuid){
        if(PCLUUIDFilter(uuid)) return false;
        return !UUID.nameUUIDFromBytes(("OfflinePlayer:" + username).getBytes(StandardCharsets.UTF_8)).equals(uuid);
    }

    public static boolean checkUserYggdrasilStatusFromRequest(String username, UUID uuid){
        return YggdrasilAuthenticator.checkAllExists(username, uuid);
    }

    @SneakyThrows
    @Subscribe
    public void onPreLogin(@Nonnull PreLoginEvent event) {
        try {
            String username = event.getUsername();

            if(!username.matches(Config.getConfigTree().getString("regex.username-regex", ".*"))){
                event.setResult(PreLoginEvent.PreLoginComponentResult.denied(Message.getMessage("auth.invalid-username").toComponent()));
                return;
            }

            AbstractAuthenticator.UserStatus accountStatus;

            try {
                accountStatus = AbstractAuthenticator.getInstance().fetchStatus(username);
            } catch (Exception e) {
                event.setResult(PreLoginEvent.PreLoginComponentResult.denied(Message.getMessage("auth.failed-to-login").toComponent()));
                throw e;
            }

            UUID uuid = event.getUniqueId();
            if(event.getUniqueId() == null) uuid = UUID.nameUUIDFromBytes(("OfflinePlayer:" + username).getBytes(StandardCharsets.UTF_8));
            LoginSession session = new LoginSession(username, uuid);
            LoginSession.getSessionMap().put(username, session);

            if (AuthXPlugin.getInstance().getProxy().getPluginManager().isLoaded("floodgate") && FloodgateHandler.isFloodgatePlayer(event.getUniqueId())) {
                return;
            }

            String cs;

            if (accountStatus == AbstractAuthenticator.UserStatus.IMPORTED) {
                event.setResult(PreLoginEvent.PreLoginComponentResult.forceOnlineMode());
                String backend = Config.getString("authentication.password.method").toLowerCase(Locale.ROOT);
                boolean localBackend = backend.equals("sqlite") || backend.equals("mysql") || backend.equals("h2");
                session.setVerifyPassword(!localBackend);
                session.setEnforcePrimaryMethod(true);
                cs = "imported";
            } else {
                boolean isPremium = false;
                if (event.getUniqueId()!=null&&!loginPremiumFailedCache.containsKey(event.getUniqueId())) {
                    switch (Config.getString("authentication.filter-method").toLowerCase(Locale.ROOT)) {
                        case "uuid" -> {
                            isPremium = checkUserYggdrasilStatusFromUUID(username, event.getUniqueId());
                        }
                        case "request" -> {
                            isPremium = checkUserYggdrasilStatusFromRequest(username, event.getUniqueId());
                        }
                        default -> { // auto
                            isPremium = checkUserYggdrasilStatusFromUUID(username, event.getUniqueId());
                            if (isPremium) {
                                isPremium = checkUserYggdrasilStatusFromRequest(username, event.getUniqueId());
                            }
                        }
                    }
                }
                if (isPremium) {
                    event.setResult(PreLoginEvent.PreLoginComponentResult.forceOnlineMode());
                    session.setVerifyPassword(false);

                    try {
                        LoginInboundConnection inboundConnection = (LoginInboundConnection) event.getConnection();
                        InitialInboundConnection initialInbound = (InitialInboundConnection) DELEGATE_FIELD.invokeExact(inboundConnection);
                        MinecraftConnection connection = initialInbound.getConnection();
                        if (!connection.isClosed()) {
                            pendingLogins.add(username);
                            connection.getChannel().closeFuture().addListener(future -> {
                                if (pendingLogins.remove(username) && Config.getBoolean("authentication.enable-fail-cache")) {
                                    loginPremiumFailedCache.put(event.getUniqueId(), System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(1));
                                }
                            });
                        }
                    }catch (Exception e){
                        pendingLogins.add(username);
                    }
                    cs = "yggdrasil";
                } else {
                    event.setResult(PreLoginEvent.PreLoginComponentResult.forceOfflineMode());
                    session.setVerifyPassword(true);
                    cs = "offline";
                }
            }
            if (Config.getBoolean("log.pre-login"))
                Logger.info("Player " + event.getUsername() + " (" + event.getUniqueId() + ") Joined the server! Detected as " + cs + " authentication.");
        }catch (Throwable e){
            Logger.error("Error when prelogin: "+e.getMessage());
            e.printStackTrace();
        }
    }

    @Subscribe
    public void onPlayerLimboConnect(LoginLimboRegisterEvent event){
        LoginSession session = LoginSession.getSessionMap().get(event.getPlayer().getUsername());
        pendingLogins.remove(event.getPlayer().getUsername());
        if(!session.isVerifyPassword()) return;
        if(AuthXPlugin.getInstance().getProxy().getPluginManager().isLoaded("floodgate") && FloodgateHandler.isFloodgatePlayer(event.getPlayer().getUniqueId())){
            return;
        }
        event.addOnJoinCallback(() -> {
            if(Config.getBoolean("log.join-limbo"))
                Logger.info("Player "+event.getPlayer().getUsername()+" is authenticating via password.");
            LimboHandler.spawnPlayer(event.getPlayer());
        });
    }

    @Subscribe(
            order = PostOrder.FIRST
    )
    public void onPlayerChat(PlayerChatEvent event){
        String msg = event.getMessage();
        if(msg!=null&&msg.equals(LoginSession.getSession(event.getPlayer().getUsername()).getPassword())){
            event.setResult(PlayerChatEvent.ChatResult.denied());
            event.getPlayer().sendMessage(Message.getMessage("chat.password-blocked").toComponent());
        }
    }

    @Subscribe
    public void onPlayerDisconnect(DisconnectEvent event){
        LoginSession.getSessionMap().remove(event.getPlayer().getUsername());
    }

    @Subscribe(order = PostOrder.FIRST)
    public void onGameProfileRequest(GameProfileRequestEvent event) {
        GameProfile profile = event.getOriginalProfile().withId(DatabaseHandler.getInstance().getUUID(event.getUsername()));
        event.setGameProfile(profile);
    }
}
