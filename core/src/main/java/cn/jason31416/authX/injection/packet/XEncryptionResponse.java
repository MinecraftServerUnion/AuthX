package cn.jason31416.authX.injection.packet;

import cn.jason31416.authX.injection.XLoginSessionHandler;
import cn.jason31416.authX.injection.XLoginSessionHandlerOld;
import cn.jason31416.authX.message.Message;
import cn.jason31416.authX.util.Config;
import cn.jason31416.authX.util.Logger;
import com.velocitypowered.proxy.connection.MinecraftSessionHandler;
import com.velocitypowered.proxy.connection.client.InitialLoginSessionHandler;
import com.velocitypowered.proxy.protocol.packet.EncryptionResponsePacket;

public class XEncryptionResponse extends EncryptionResponsePacket {
    @Override
    public boolean handle(MinecraftSessionHandler handler) {
        if (!(handler instanceof InitialLoginSessionHandler)) {
            return super.handle(handler);
        }

        XLoginSessionHandler multiInitialLoginSessionHandler = new XLoginSessionHandler((InitialLoginSessionHandler) handler);
        try {
            multiInitialLoginSessionHandler.handle(this);
        } catch (Throwable e) {
            if (multiInitialLoginSessionHandler.isEncrypted()) {
                multiInitialLoginSessionHandler.getInbound().disconnect(Message.getMessage("sessionhandler.internal-error").toComponent());
            }
            multiInitialLoginSessionHandler.getMcConnection().close(true);
            Logger.error("An exception occurred while processing a login request. "+e.getMessage());
        }

        return true;
    }
}
