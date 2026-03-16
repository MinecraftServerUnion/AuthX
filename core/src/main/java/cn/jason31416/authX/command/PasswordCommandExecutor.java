package cn.jason31416.authX.command;

import cn.jason31416.authX.handler.DatabaseHandler;
import cn.jason31416.authX.message.Message;
import cn.jason31416.authX.util.Config;
import cn.jason31416.authx.api.AbstractAuthenticator;
import com.velocitypowered.api.command.CommandSource;

import java.util.Locale;

public class PasswordCommandExecutor {
    private PasswordCommandExecutor() {}

    private static boolean isLocalPasswordBackend() {
        String backend = Config.getString("authentication.password.method").toLowerCase(Locale.ROOT);
        return backend.equals("sqlite") || backend.equals("mysql") || backend.equals("h2");
    }

    static boolean shouldRequireOldPassword(String username) {
        if (!Config.getBoolean("command.change-password.need-old-password")) {
            return false;
        }
        String backend = Config.getString("authentication.password.method").toLowerCase(Locale.ROOT);
        if (backend.equals("uniauth")) {
            return DatabaseHandler.getInstance().isPasswordSet(username);
        }
        if (!isLocalPasswordBackend()) {
            return true;
        }
        return DatabaseHandler.getInstance().hasPassword(username);
    }

    public static void executeChangePassword(CommandSource source, String username, String[] args, int argumentOffset) {
        boolean needOldPassword = shouldRequireOldPassword(username);
        String newPassword;
        String oldPassword = null;

        if (needOldPassword) {
            if (args.length != argumentOffset + 2) {
                source.sendMessage(Message.getMessage("command.change-password.invalid-format-need-old-password").toComponent());
                return;
            }
            oldPassword = args[argumentOffset];
            newPassword = args[argumentOffset + 1];

            if (!AbstractAuthenticator.getInstance().authenticate(username, oldPassword).success) {
                source.sendMessage(Message.getMessage("command.change-password.invalid-password").toComponent());
                return;
            }
        } else {
            if (args.length != argumentOffset + 1) {
                source.sendMessage(Message.getMessage("command.change-password.invalid-format-no-old-password").toComponent());
                return;
            }
            newPassword = args[argumentOffset];
        }

        if (!newPassword.matches(Config.getString("regex.password-regex"))) {
            source.sendMessage(Message.getMessage("command.change-password.invalid-password-format").toComponent());
            return;
        }

        AbstractAuthenticator.RequestResult result;
        if (needOldPassword) {
            result = AbstractAuthenticator.getInstance().changePasswordWithOld(username, oldPassword, newPassword);
        } else {
            result = AbstractAuthenticator.getInstance().changePassword(username, newPassword);
        }

        if (!result.success) {
            source.sendMessage(Message.getMessage("command.change-password.invalid-password").toComponent());
            return;
        }
        source.sendMessage(Message.getMessage("command.change-password.success").toComponent());
    }
}
