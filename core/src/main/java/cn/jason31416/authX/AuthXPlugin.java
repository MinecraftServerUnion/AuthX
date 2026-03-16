package cn.jason31416.authX;

import cn.jason31416.authX.handler.LoginSession;
import cn.jason31416.authX.hook.TABHandler;
import cn.jason31416.authx.api.*;
import cn.jason31416.authX.authbackend.LocalAuthenticator;
import cn.jason31416.authX.authbackend.UniauthAuthenticator;
import cn.jason31416.authX.command.AccountCommandHandler;
import cn.jason31416.authX.command.AdminCommandHandler;
import cn.jason31416.authX.command.ChangePassCommandHandler;
import cn.jason31416.authX.handler.DatabaseHandler;
import cn.jason31416.authX.handler.EventListener;
import cn.jason31416.authX.handler.LimboHandler;
import cn.jason31416.authX.injection.PacketInjector;
import cn.jason31416.authX.injection.XLoginSessionHandler;
import cn.jason31416.authX.message.MessageLoader;
import cn.jason31416.authX.util.Config;
import com.google.inject.Inject;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.plugin.Dependency;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.plugin.PluginContainer;
import com.velocitypowered.api.plugin.annotation.DataDirectory;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.scheduler.Scheduler;
import lombok.Getter;
import lombok.SneakyThrows;
import net.elytrium.limboapi.api.LimboFactory;
import net.elytrium.limboapi.api.chunk.Dimension;
import net.elytrium.limboapi.api.chunk.VirtualWorld;
import net.elytrium.limboapi.api.file.BuiltInWorldFileType;
import net.elytrium.limboapi.api.file.WorldFile;
import net.elytrium.limboapi.api.player.GameMode;
import org.bstats.charts.SimplePie;
import org.bstats.charts.SingleLineChart;
import org.bstats.velocity.Metrics;
import org.slf4j.Logger;

import javax.annotation.Nonnull;
import java.io.*;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Plugin(id = "authx", name = "AuthX", version = "2.1.4", authors = {"Jason31416", "oneLiLi"},
        dependencies = {
                @Dependency(id = "limboapi", optional = false),
                @Dependency(id = "floodgate", optional = true),
                @Dependency(id = "tab", optional = true)
        })
public class AuthXPlugin implements AuthXApi {
    @Getter
    public static AuthXPlugin instance;

    @Getter
    private final Logger logger;
    @Getter
    private final ProxyServer proxy;
    @Getter
    private final File dataDirectory;

    @Getter
    private final Metrics.Factory metricsFactory;

    public static Scheduler getScheduler() {
        return instance.proxy.getScheduler();
    }

    @SneakyThrows
    public void init() {
        if(!dataDirectory.exists()) dataDirectory.mkdirs();

        Config.init();
        MessageLoader.initialize();

        DatabaseHandler.getInstance().init();

        LimboFactory factory = (LimboFactory) proxy.getPluginManager().getPlugin("limboapi").flatMap(PluginContainer::getInstance).orElseThrow();
        VirtualWorld authWorld = factory.createVirtualWorld(
                Dimension.valueOf(Config.getString("limbo-world.dimension").toUpperCase(Locale.ROOT)),
                Config.getDouble("limbo-world.position.x"), Config.getDouble("limbo-world.position.y"), Config.getDouble("limbo-world.position.z"),
                (float)Config.getDouble("limbo-world.position.yaw"), (float)Config.getDouble("limbo-world.position.pitch")
        );
        if(!Config.getString("limbo-world.world-loader.type").equalsIgnoreCase("VOID")){
            WorldFile worldFile = factory.openWorldFile(BuiltInWorldFileType.valueOf(Config.getString("limbo-world.world-loader.type")), new File(dataDirectory, Config.getString("limbo-world.world-loader.file-name")).toPath());
            worldFile.toWorld(
                    factory,
                    authWorld,
                    Config.getInt("limbo-world.world-loader.offset-x"),
                    Config.getInt("limbo-world.world-loader.offset-y"),
                    Config.getInt("limbo-world.world-loader.offset-z")
            );
        }

        if(LimboHandler.limboWorld!= null) LimboHandler.limboWorld.dispose();

        LimboHandler.limboWorld = factory
                .createLimbo(authWorld)
                .setName("AuthXLimbo")
                .setGameMode(GameMode.valueOf(Config.getString("limbo-world.gamemode").toUpperCase(Locale.ROOT)));

        AbstractAuthenticator.instance = switch(Config.getString("authentication.password.method").toLowerCase(Locale.ROOT)){
            case "uniauth" -> new UniauthAuthenticator();
            case "sqlite" -> new LocalAuthenticator();
            case "mysql" -> new LocalAuthenticator();
            case "h2" -> new LocalAuthenticator();
            default -> throw new IllegalArgumentException("Invalid authentication.password.method: " + Config.getString("authentication.password.method"));
        };
        AbstractAuthenticator.getInstance().initialize();

        if(Config.getConfigTree().getBoolean("bstats", false)) {
            int pluginId = 30252;
            Metrics metrics = metricsFactory.make(this, pluginId);
        }
    }

    @Inject
    public AuthXPlugin(@Nonnull ProxyServer proxy, @Nonnull Logger logger, @Nonnull @DataDirectory Path dataDirectory, Metrics.Factory metricsFactory) {
        this.proxy = proxy;
        this.logger = logger;
        this.dataDirectory = dataDirectory.toFile();
        this.metricsFactory = metricsFactory;

        instance = this;
    }

    @Subscribe
    @SneakyThrows
    public void onProxyInitialization(ProxyInitializeEvent event) {
        AuthX.setApiInstance(this);
        init();

        proxy.getEventManager().register(instance, new EventListener());

        proxy.getCommandManager().register(
                proxy.getCommandManager().metaBuilder("authx").plugin(this).build(),
                AdminCommandHandler.INSTANCE
        );

        proxy.getCommandManager().register(
                proxy.getCommandManager().metaBuilder("account").plugin(this).build(),
                AccountCommandHandler.INSTANCE
        );
        proxy.getCommandManager().register(
                proxy.getCommandManager().metaBuilder("changepass").plugin(this).build(),
                ChangePassCommandHandler.INSTANCE
        );

        getScheduler().buildTask(this, () -> {
            for(UUID uuid: new HashSet<>(EventListener.loginPremiumFailedCache.keySet())){
                if(EventListener.loginPremiumFailedCache.get(uuid) < System.currentTimeMillis()){
                    EventListener.loginPremiumFailedCache.remove(uuid);
                }
            }
        }).repeat(1, TimeUnit.HOURS).schedule();

        try {
            XLoginSessionHandler.init();
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize login session handler", e);
        }

        PacketInjector.inject();

        if(getProxy().getPluginManager().isLoaded("tab")){
            TABHandler.registerPlaceholder();
        }

        logger.info("AuthX has been enabled!");
    }

    public void info(String message) {
        logger.info(message);
    }

    public void error(String message) {
        logger.error(message);
    }

    public void warning(String message) {
        logger.warn(message);
    }

    @Override
    public AbstractAuthenticator getAuthenticator() {
        return AbstractAuthenticator.getInstance();
    }

    @Override
    public IDatabaseHandler getDatabaseHandler() {
        return DatabaseHandler.getInstance();
    }

    @Override
    public String getVersion() {
        return "Beta 2.2";
    }

    @Override
    public ILoginSession getPlayerData(String username) {
        return LoginSession.getSession(username);
    }
}
