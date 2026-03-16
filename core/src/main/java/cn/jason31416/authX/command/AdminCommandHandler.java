package cn.jason31416.authX.command;

import cn.jason31416.authX.AuthXPlugin;
import cn.jason31416.authx.api.AbstractAuthenticator;
import cn.jason31416.authX.authbackend.UniauthAuthenticator;
import cn.jason31416.authX.handler.DatabaseHandler;
import cn.jason31416.authX.handler.EventListener;
import cn.jason31416.authX.handler.MultiLoginUuidMigrator;
import cn.jason31416.authX.message.Message;
import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.util.UuidUtils;
import org.jetbrains.annotations.NotNull;

import javax.annotation.Nonnull;
import java.util.List;
import java.util.UUID;

public class AdminCommandHandler implements SimpleCommand {
    public static final AdminCommandHandler INSTANCE = new AdminCommandHandler();

    @Override
    public void execute(final @NotNull SimpleCommand.Invocation invocation) {
        String subCommand;
        if(invocation.arguments().length>0){
            subCommand = invocation.arguments()[0];
        }else{
            subCommand = "";
        }
        if((invocation.source() instanceof Player)&&!invocation.source().hasPermission("authx.admin")){
            invocation.source().sendMessage(Message.getMessage("command.no-permission").toComponent());
            return;
        }
        switch (subCommand){
            case "changepass" -> {
                if(invocation.arguments().length<3){
                    invocation.source().sendMessage(Message.getMessage("command.force-change-password.invalid-format").toComponent());
                    return;
                }
                String newPassword = invocation.arguments()[2], username = invocation.arguments()[1];
                if(AbstractAuthenticator.getInstance().fetchStatus(username) == AbstractAuthenticator.UserStatus.NOT_EXIST){
                    invocation.source().sendMessage(Message.getMessage("command.player-not-exists").add("player", username).toComponent());
                    return;
                }
                AbstractAuthenticator.getInstance().changePassword(username, newPassword);
                invocation.source().sendMessage(Message.getMessage("command.force-change-password.success").add("player", username).toComponent());
            }
            case "unregister" -> {
                if(invocation.arguments().length<2){
                    invocation.source().sendMessage(Message.getMessage("command.force-unregister.invalid-format").toComponent());
                    return;
                }
                String username = invocation.arguments()[1];
                if(AbstractAuthenticator.getInstance().fetchStatus(username) == AbstractAuthenticator.UserStatus.NOT_EXIST){
                    invocation.source().sendMessage(Message.getMessage("command.player-not-exists").add("player", username).toComponent());
                    return;
                }
                if(AbstractAuthenticator.getInstance() instanceof UniauthAuthenticator){
                    invocation.source().sendMessage(new Message("&cUniauth does not support unregistering users!").toComponent());
                    return;
                }
                AbstractAuthenticator.getInstance().unregister(username);
                invocation.source().sendMessage(Message.getMessage("command.change-password.success").toComponent());
            }
            case "reload" -> {
                AuthXPlugin.instance.init();
                invocation.source().sendMessage(Message.getMessage("command.reload.success").toComponent());
            }
            case "recover" -> {
                try{
                    int cnt = UniauthAuthenticator.attemptRecovery();
                    invocation.source().sendMessage(Message.getMessage("command.recover.success").add("count", cnt).toComponent());
                }catch (Exception e){
                    invocation.source().sendMessage(Message.getMessage("command.recover.failed").add("reason", e.getMessage()).toComponent());
                }
            }
            case "setuuid" -> {
                if(invocation.arguments().length<2){
                    invocation.source().sendMessage(Message.getMessage("command.set-uuid.invalid-format").toComponent());
                    return;
                }
                UUID uuid;
                String username = invocation.arguments()[1];
                if(invocation.arguments().length >= 3){
                    try {
                        uuid = UUID.fromString(invocation.arguments()[2]);
                    }catch (Exception e){
                        invocation.source().sendMessage(Message.getMessage("command.set-uuid.invalid-uuid").toComponent());
                        return;
                    }
                }else{
                    uuid = UuidUtils.generateOfflinePlayerUuid(username);
                }
                DatabaseHandler.getInstance().setUUID(username, uuid);
                invocation.source().sendMessage(Message.getMessage("command.set-uuid.success").add("player", username).add("uuid", uuid.toString()).toComponent());
            }
            case "clearcache" -> {
                EventListener.loginPremiumFailedCache.clear();
                invocation.source().sendMessage(new Message("&aCleared user authentication cache!").toComponent());
            }
            case "migrateml" -> {
                boolean dryRun = invocation.arguments().length >= 2 && invocation.arguments()[1].equalsIgnoreCase("dryrun");
                if (invocation.arguments().length >= 2 && !dryRun) {
                    invocation.source().sendMessage(Message.getMessage("command.migrate-ml.invalid-format").toComponent());
                    return;
                }
                if (MultiLoginUuidMigrator.isRunning()) {
                    invocation.source().sendMessage(Message.getMessage("command.migrate-ml.already-running").toComponent());
                    return;
                }
                invocation.source().sendMessage(Message.getMessage("command.migrate-ml.start")
                        .add("mode", dryRun ? "dryrun" : "import")
                        .toComponent());
                AuthXPlugin.getScheduler().buildTask(AuthXPlugin.getInstance(), () -> {
                    try {
                        var result = MultiLoginUuidMigrator.migrate(dryRun);
                        invocation.source().sendMessage(Message.getMessage("command.migrate-ml.success")
                                .add("mode", result.dryRun() ? "dryrun" : "import")
                                .add("total", result.total())
                                .add("imported", result.imported())
                                .add("skipped_existing", result.skippedExisting())
                                .add("skipped_invalid", result.skippedInvalid())
                                .add("errors", result.errors())
                                .add("duration", String.format("%.2f", result.durationMs() / 1000.0))
                                .toComponent());
                    } catch (Exception e) {
                        invocation.source().sendMessage(Message.getMessage("command.migrate-ml.failed")
                                .add("reason", e.getMessage())
                                .toComponent());
                    }
                }).schedule();
            }
            case "" -> {
                invocation.source().sendMessage(new Message("&aRunning &b&lAuthX v2 &aby Jason31416!").toComponent());
            }
            default -> {
                invocation.source().sendMessage(Message.getMessage("command.default").toComponent());
            }
        }
    }
    @Override
    public List<String> suggest(final @Nonnull Invocation invocation) {
        if(invocation.arguments().length<=1)
            return List.of("changepass", "unregister", "reload", "setuuid", "clearcache", "migrateml");
        else if(invocation.arguments().length == 2){
            return switch (invocation.arguments()[0]){
                case "changepass" -> List.of(Message.getMessage("tab-complete.force-change-password.player").toString());
                case "unregister" -> List.of(Message.getMessage("command.force-change-password.new").toString());
                case "setuuid" -> List.of(Message.getMessage("tab-complete.set-uuid.player").toString());
                case "migrateml" -> List.of("dryrun");
                default -> List.of();
            };
        }else if(invocation.arguments().length == 3){
            return switch (invocation.arguments()[0]){
                case "changepass" -> List.of(Message.getMessage("command.force-change-password.new").toString());
                case "setuuid" -> List.of(Message.getMessage("tab-complete.set-uuid.uuid").toString());
                default -> List.of();
            };
        }
        return List.of();
    }
}
