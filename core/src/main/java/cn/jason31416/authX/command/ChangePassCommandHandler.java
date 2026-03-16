package cn.jason31416.authX.command;

import cn.jason31416.authX.message.Message;
import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.Player;
import org.jetbrains.annotations.NotNull;

import javax.annotation.Nonnull;
import java.util.List;

public class ChangePassCommandHandler implements SimpleCommand {
    public static final ChangePassCommandHandler INSTANCE = new ChangePassCommandHandler();

    @Override
    public void execute(final @NotNull Invocation invocation) {
        CommandSource source = invocation.source();
        if (!(source instanceof Player pl)) {
            source.sendMessage(Message.getMessage("command.player-command").toComponent());
            return;
        }
        PasswordCommandExecutor.executeChangePassword(source, pl.getUsername(), invocation.arguments(), 0);
    }

    @Override
    public List<String> suggest(final @Nonnull Invocation invocation) {
        boolean needOldPassword = false;
        if (invocation.source() instanceof Player pl) {
            needOldPassword = PasswordCommandExecutor.shouldRequireOldPassword(pl.getUsername());
        }
        if (invocation.arguments().length == 0) {
            return List.of((needOldPassword ? Message.getMessage("tab-complete.change-password.old") : Message.getMessage("tab-complete.change-password.new")).toString());
        }
        if (invocation.arguments().length == 1) {
            return needOldPassword ? List.of(Message.getMessage("tab-complete.change-password.new").toString()) : List.of();
        }
        return List.of();
    }
}
