package cn.jason31416.authX.command;

import cn.jason31416.authX.message.Message;
import cn.jason31416.authX.util.Config;
import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.Player;
import org.jetbrains.annotations.NotNull;

import javax.annotation.Nonnull;
import java.util.List;

public class AccountCommandHandler implements SimpleCommand {
    public static final AccountCommandHandler INSTANCE = new AccountCommandHandler();

    @Override
    public void execute(final @NotNull SimpleCommand.Invocation invocation) {
        CommandSource source = invocation.source();
        if(!(source instanceof Player pl)) {
            invocation.source().sendMessage(Message.getMessage("command.player-command").toComponent());
            return;
        }
        String subCommand;
        if(invocation.arguments().length>0){
            subCommand = invocation.arguments()[0];
        }else{
            subCommand = "";
        }
        String username = pl.getUsername();
        switch (subCommand){
            case "changepass" -> {
                PasswordCommandExecutor.executeChangePassword(invocation.source(), username, invocation.arguments(), 1);
            }
            default -> {
                invocation.source().sendMessage(Message.getMessage("command.default").toComponent());
            }
        }
    }
    @Override
    public List<String> suggest(final @Nonnull Invocation invocation) {
        boolean needOldPassword = false;
        if (invocation.source() instanceof Player pl) {
            needOldPassword = PasswordCommandExecutor.shouldRequireOldPassword(pl.getUsername());
        } else {
            needOldPassword = Config.getBoolean("command.change-password.need-old-password");
        }

        if(invocation.arguments().length<=1)
            return List.of("changepass");
        else if(invocation.arguments().length == 2){
            return switch (invocation.arguments()[0]){
                case "changepass" -> List.of(needOldPassword ?Message.getMessage("tab-complete.change-password.old").toString():Message.getMessage("tab-complete.change-password.new").toString());
                default -> List.of();
            };
        }else if(invocation.arguments().length == 3){
            return switch (invocation.arguments()[0]){
                case "changepass" -> needOldPassword ? List.of(Message.getMessage("tab-complete.change-password.new").toString()) : List.of();
                default -> List.of();
            };
        }
        return List.of();
    }
}
