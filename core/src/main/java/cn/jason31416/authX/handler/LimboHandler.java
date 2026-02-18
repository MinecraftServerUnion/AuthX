package cn.jason31416.authX.handler;

import cn.jason31416.authX.AuthXPlugin;
import cn.jason31416.authX.util.Logger;
import cn.jason31416.authx.api.AbstractAuthenticator;
import cn.jason31416.authX.message.Message;
import cn.jason31416.authX.util.Config;
import com.velocitypowered.api.network.ProtocolVersion;
import com.velocitypowered.api.proxy.Player;
import net.elytrium.limboapi.api.Limbo;
import net.elytrium.limboapi.api.LimboSessionHandler;
import net.elytrium.limboapi.api.player.LimboPlayer;
import net.kyori.adventure.bossbar.BossBar;
import net.kyori.adventure.key.Key;
import net.kyori.adventure.text.Component;

import javax.annotation.Nonnull;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;

public class LimboHandler implements LimboSessionHandler {
    public static Map<String, LimboHandler> authPlayers = new HashMap<>();
    public static Limbo limboWorld = null;

    private String password, email, code;
    private LimboPlayer limboPlayer;
    private Player player;
    private long joinTime;
    private int attemptCount = Config.getInt("authentication.password.attempt-count");
    private AuthStage currentStage = AuthStage.UNKNOWN;
    private AtomicBoolean isAuthenticating = new AtomicBoolean(true);

    public LimboHandler(Player player) {
        this.player = player;
    }

    private final BossBar bossBar = BossBar.bossBar(
            Component.empty(),
            1.0F,
            BossBar.Color.BLUE,
            BossBar.Overlay.PROGRESS
    );

    private void switchStage(AuthStage stage) {
        if(stage == AuthStage.LOGIN) {
            player.showBossBar(this.bossBar);
        }else{
            player.hideBossBar(this.bossBar);
        }
        currentStage = stage;
        player.sendMessage(Message.getMessage("auth.message-hint."+currentStage.name().toLowerCase(Locale.ROOT)).toComponent());
    }

    public enum AuthStage {
        UNKNOWN,
        LOGIN,
        REGISTER_PASSWORD,
        REGISTER_CONFIRM_PASSWORD
    }

    public void finishLogin() {
        limboPlayer.disconnect();

        var session = LoginSession.getSessionMap().get(player.getUsername());
        if(session == null) return;
        if(session.getAuthMethod()!=null&&!session.getAuthMethod().isEmpty()){
            DatabaseHandler.getInstance().addAuthMethod(player.getUsername(), session.getAuthMethod());
        }else{
            session.setAuthMethod("offline");
        }
    }

    public static void spawnPlayer(@Nonnull Player player) {
        limboWorld.spawnPlayer(player, new LimboHandler(player));
    }

    @Override
    public void onSpawn(Limbo limbo, LimboPlayer limboPlayer) {
        this.limboPlayer = limboPlayer;
        this.limboPlayer.disableFalling();

        joinTime = System.currentTimeMillis();

        if(LoginSession.getSession(player.getUsername()).getPasswordIntroMessage() != null){
            player.sendMessage(LoginSession.getSession(player.getUsername()).getPasswordIntroMessage().toComponent());
        }

        authPlayers.put(player.getGameProfile().getName(), this);

        long authTime = Config.getInt("authentication.password.auth-time")*1000L;
        float multiplier = 1000.0F / authTime;

        AuthXPlugin.getScheduler().buildTask(AuthXPlugin.getInstance(), () -> {
            try {
                if(AbstractAuthenticator.getInstance().fetchStatus(player.getUsername()) == AbstractAuthenticator.UserStatus.REGISTERED) {
                    switchStage(AuthStage.LOGIN);
                } else {
                    switchStage(AuthStage.REGISTER_PASSWORD);
                }
            }catch (Exception e){
                player.disconnect(Message.getMessage("auth.failed-to-connect-to-backend").toComponent());
                throw e;
            }
        }).schedule();

        AuthXPlugin.getScheduler().buildTask(AuthXPlugin.getInstance(), t -> {
            if(!isAuthenticating.get()){
                t.cancel();
                return;
            }
            if (currentStage.equals(AuthStage.LOGIN) || currentStage.equals(AuthStage.REGISTER_PASSWORD) || currentStage.equals(AuthStage.REGISTER_CONFIRM_PASSWORD)) {
                if (System.currentTimeMillis() - joinTime > authTime) {
                    player.disconnect(Message.getMessage("auth.timeout").toComponent());
                    isAuthenticating.set(false);
                } else {
                    float secondsLeft = (authTime - (System.currentTimeMillis() - joinTime)) / 1000.0F;
                    bossBar.name(Message.getMessage("auth.auth-bar-name").add("time", (int) secondsLeft).toComponent());
                    bossBar.progress(Math.min(1.0F, secondsLeft * multiplier));
                }
            }
            player.sendActionBar(Message.getMessage("auth.message-hint." + currentStage.name().toLowerCase(Locale.ROOT)).toComponent());
        }).repeat(1L, TimeUnit.SECONDS).schedule();
    }
    @Override
    public void onDisconnect() {
        authPlayers.remove(player.getGameProfile().getName());
        isAuthenticating.set(false);
        player.hideBossBar(bossBar);
    }
    @Override
    public void onChat(String message) {
        switch (currentStage){
            case LOGIN -> {
                if (attemptCount > 0) {
                    attemptCount--;
                    password = message;
                    player.sendMessage(Message.getMessage("auth.user-input").add("input", password.replaceAll(".", "*")).toComponent());
                    AuthXPlugin.getScheduler().buildTask(AuthXPlugin.getInstance(), () -> {
                        AbstractAuthenticator.RequestResult result = AbstractAuthenticator.getInstance().authenticate(player.getUsername(), password);
                        if (result == AbstractAuthenticator.RequestResult.SUCCESS) {
                            player.sendMessage(Message.getMessage("auth.login-success").toComponent());
                            LoginSession.getSession(player.getUsername()).setPassword(password);
                            finishLogin();
                        }else if(result == AbstractAuthenticator.RequestResult.INVALID_PASSWORD){
                            player.sendMessage(Message.getMessage("auth.invalid-password").toComponent());
                            switchStage(AuthStage.LOGIN);
                        }else if(result == AbstractAuthenticator.RequestResult.USER_DOESNT_EXIST){
                            switchStage(AuthStage.REGISTER_PASSWORD);
                        }else if(result == AbstractAuthenticator.RequestResult.EMAIL_NOT_LINKED){
                            player.sendMessage(Message.getMessage("auth.email-not-verified").toComponent());
                            LoginSession.getSession(player.getUsername()).setPassword(password);
                            finishLogin();
                        }else{
                            player.sendMessage(Message.getMessage("auth.unknown-error").toComponent());
                        }
                    }).schedule();
                }else {
                    player.disconnect(Message.getMessage("auth.max-attempts").toComponent());
                }
            }
            case REGISTER_PASSWORD -> {
                player.sendMessage(Message.getMessage("auth.user-input").add("input", message.replaceAll(".", "*")).toComponent());
                if(Pattern.matches(Config.getString("regex.password-regex"), message)){
                    password = message;
                    switchStage(AuthStage.REGISTER_CONFIRM_PASSWORD);
                }else{
                    player.sendMessage(Message.getMessage("auth.password-doesnt-match-regex").toComponent());
                    switchStage(AuthStage.REGISTER_PASSWORD);
                }
            }
            case REGISTER_CONFIRM_PASSWORD -> {
                if(!message.equals(password)){
                    player.sendMessage(Message.getMessage("auth.passwords-dont-match").toComponent());
                    switchStage(AuthStage.REGISTER_PASSWORD);
                    return;
                }
                player.sendMessage(Message.getMessage("auth.user-input").add("input", message.replaceAll(".", "*")).toComponent());

                var ret = AbstractAuthenticator.getInstance().forceRegister(player.getUsername(), password);
                if(ret == AbstractAuthenticator.RequestResult.SUCCESS){
                    player.sendMessage(Message.getMessage("auth.register-success").toComponent());
                    finishLogin();
                }else if(ret == AbstractAuthenticator.RequestResult.USER_ALREADY_EXISTS){
                    player.sendMessage(Message.getMessage("auth.user-already-exists").toComponent());
                }else{
                    player.sendMessage(Message.getMessage("auth.unknown-error").toComponent());
                }
            }
        }
    }
}
