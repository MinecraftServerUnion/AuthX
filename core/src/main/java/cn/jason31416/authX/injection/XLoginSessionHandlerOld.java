/*
This file contains partial code from the MultiLogin project
 */

package cn.jason31416.authX.injection;

import cn.jason31416.authX.AuthXPlugin;
import cn.jason31416.authX.handler.LoginSession;
import cn.jason31416.authX.handler.YggdrasilAuthenticator;
import cn.jason31416.authX.injection.accessor.Accessor;
import cn.jason31416.authX.injection.accessor.EnumAccessor;
import cn.jason31416.authX.message.Message;
import cn.jason31416.authX.util.Config;
import cn.jason31416.authX.util.Logger;
import cn.jason31416.authX.util.PlayerProfile;
import com.google.common.primitives.Longs;
import com.velocitypowered.api.proxy.crypto.IdentifiedKey;
import com.velocitypowered.api.util.GameProfile;
import com.velocitypowered.api.util.UuidUtils;
import com.velocitypowered.proxy.VelocityServer;
import com.velocitypowered.proxy.connection.MinecraftConnection;
import com.velocitypowered.proxy.connection.client.AuthSessionHandler;
import com.velocitypowered.proxy.connection.client.InitialLoginSessionHandler;
import com.velocitypowered.proxy.connection.client.LoginInboundConnection;
import com.velocitypowered.proxy.crypto.EncryptionUtils;
import com.velocitypowered.proxy.protocol.StateRegistry;
import com.velocitypowered.proxy.protocol.packet.EncryptionRequestPacket;
import com.velocitypowered.proxy.protocol.packet.EncryptionResponsePacket;
import com.velocitypowered.proxy.protocol.packet.ServerLoginPacket;
import lombok.Getter;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.concurrent.ThreadLocalRandom;

@Getter
public class XLoginSessionHandlerOld {
    private static EnumAccessor loginStatsEnumAccessor;
    private static Accessor initialLoginSessionHandlerAccessor;

    private static Enum<?> loginStateEnum$LOGIN_PACKET_EXPECTED;
    private static Enum<?> loginStateEnum$LOGIN_PACKET_RECEIVED;
    private static Enum<?> loginStateEnum$ENCRYPTION_REQUEST_SENT;
    private static Enum<?> loginStateEnum$ENCRYPTION_RESPONSE_RECEIVED;

    private static MethodHandle assertStateMethod;
    private static MethodHandle setCurrentStateField;
    private static MethodHandle getLoginField;
    private static MethodHandle getVerifyField;
    private static MethodHandle getServerField;
    private static MethodHandle getInboundField;
    private static MethodHandle getMcConnectionField;
    private static MethodHandle getCurrentStateField;
    private static MethodHandle authSessionHandler_allArgsConstructor;

    private final InitialLoginSessionHandler initialLoginSessionHandler;
    private final MinecraftConnection mcConnection;
    private final LoginInboundConnection inbound;
    private boolean encrypted = false;
    private final VelocityServer server;
    private ServerLoginPacket login;
    private byte[] verify;

    public XLoginSessionHandlerOld(InitialLoginSessionHandler initialLoginSessionHandler) {
        this.initialLoginSessionHandler = initialLoginSessionHandler;
        try {
            this.server = (VelocityServer) getServerField.invoke(initialLoginSessionHandler);
            this.mcConnection = (MinecraftConnection) getMcConnectionField.invoke(initialLoginSessionHandler);
            this.inbound = (LoginInboundConnection) getInboundField.invoke(initialLoginSessionHandler);
        } catch (Throwable e) {
            throw new RuntimeException(e);
        }
    }


    public static void init() throws ClassNotFoundException, NoSuchMethodException, IllegalAccessException, NoSuchFieldException {
        Class<InitialLoginSessionHandler> initialLoginSessionHandlerClass = InitialLoginSessionHandler.class;
        initialLoginSessionHandlerAccessor = new Accessor(initialLoginSessionHandlerClass);

        Class<?> loginStateEnum = Class.forName("com.velocitypowered.proxy.connection.client.InitialLoginSessionHandler$LoginState");
        loginStatsEnumAccessor = new EnumAccessor(loginStateEnum);

        loginStateEnum$LOGIN_PACKET_EXPECTED = loginStatsEnumAccessor.findByName("LOGIN_PACKET_EXPECTED");
        loginStateEnum$LOGIN_PACKET_RECEIVED = loginStatsEnumAccessor.findByName("LOGIN_PACKET_RECEIVED");
        loginStateEnum$ENCRYPTION_REQUEST_SENT = loginStatsEnumAccessor.findByName("ENCRYPTION_REQUEST_SENT");
        loginStateEnum$ENCRYPTION_RESPONSE_RECEIVED = loginStatsEnumAccessor.findByName("ENCRYPTION_RESPONSE_RECEIVED");

        MethodHandles.Lookup lookup = MethodHandles.lookup();

        assertStateMethod = lookup.unreflect(ReflectionUtil.handleAccessible(
                initialLoginSessionHandlerAccessor.findFirstMethodByName(true, "assertState")
        ));

        Field currentState = ReflectionUtil.handleAccessible(
                initialLoginSessionHandlerClass.getDeclaredField("currentState")
        );
        getCurrentStateField = lookup.unreflectGetter(currentState);
        setCurrentStateField = lookup.unreflectSetter(currentState);

        getLoginField = lookup.unreflectGetter(ReflectionUtil.handleAccessible(
                initialLoginSessionHandlerAccessor.findFirstFieldByType(true, ServerLoginPacket.class)
        ));

        getVerifyField = lookup.unreflectGetter(ReflectionUtil.handleAccessible(
                initialLoginSessionHandlerAccessor.findFirstFieldByType(true, byte[].class)
        ));

        getServerField = lookup.unreflectGetter(ReflectionUtil.handleAccessible(
                initialLoginSessionHandlerAccessor.findFirstFieldByType(true, VelocityServer.class)
        ));

        getInboundField = lookup.unreflectGetter(ReflectionUtil.handleAccessible(
                initialLoginSessionHandlerAccessor.findFirstFieldByType(true, LoginInboundConnection.class)
        ));

        getMcConnectionField = lookup.unreflectGetter(ReflectionUtil.handleAccessible(
                initialLoginSessionHandlerAccessor.findFirstFieldByType(true, MinecraftConnection.class)
        ));


        authSessionHandler_allArgsConstructor = lookup.unreflectConstructor(ReflectionUtil.handleAccessible(
                AuthSessionHandler.class.getDeclaredConstructor(
                        VelocityServer.class,
                        LoginInboundConnection.class,
                        GameProfile.class,
                        boolean.class
                )
        ));
    }

    private void initValues() throws Throwable {
        this.login = (ServerLoginPacket) getLoginField.invoke(initialLoginSessionHandler);
        this.verify = (byte[]) getVerifyField.invoke(initialLoginSessionHandler);
    }

    public void handle(EncryptionResponsePacket packet) throws Throwable {
        try {
            initValues();
            assertStateMethod.invoke(initialLoginSessionHandler, loginStateEnum$ENCRYPTION_REQUEST_SENT);
            setCurrentStateField.invoke(initialLoginSessionHandler, loginStateEnum$ENCRYPTION_RESPONSE_RECEIVED);

            ServerLoginPacket login = this.login;
            if (login == null) {
                throw new IllegalStateException("No ServerLogin packet received yet.");
            }
            if (this.verify.length == 0) {
                throw new IllegalStateException("No EncryptionRequest packet sent yet.");
            }

            try {
                KeyPair serverKeyPair = this.server.getServerKeyPair();
                if (this.inbound.getIdentifiedKey() != null) {
                    IdentifiedKey playerKey = this.inbound.getIdentifiedKey();
                    if (!playerKey.verifyDataSignature(packet.getVerifyToken(), this.verify, Longs.toByteArray(packet.getSalt()))) {
                        throw new IllegalStateException("Invalid client public signature.");
                    }
                } else {
                    byte[] decryptedSharedSecret = EncryptionUtils.decryptRsa(serverKeyPair, packet.getVerifyToken());
                    if (!MessageDigest.isEqual(this.verify, decryptedSharedSecret)) {
                        throw new IllegalStateException("Unable to successfully decrypt the verification token.");
                    }
                }

                byte[] decryptedSharedSecret = EncryptionUtils.decryptRsa(serverKeyPair, packet.getSharedSecret());

                encrypted = true;

                String username = login.getUsername();
                String serverId = EncryptionUtils.generateServerId(decryptedSharedSecret, serverKeyPair.getPublic());
                String playerIp = ((InetSocketAddress) this.mcConnection.getRemoteAddress()).getHostString();

                AuthXPlugin.getInstance().getProxy().getScheduler().buildTask(AuthXPlugin.getInstance(), () -> {
                    PlayerProfile playerProfile;
                    try {
                        playerProfile = YggdrasilAuthenticator.authenticate(username, serverId, playerIp);
                    }catch (Exception e){
                        playerProfile = null;
                    }
//                    Logger.info("Authed: "+(playerProfile == null));
                    try {
                        if (mcConnection.getChannel().eventLoop().submit(() -> {
                            if (this.mcConnection.isClosed()) return false;
                            try {
                                this.mcConnection.enableEncryption(decryptedSharedSecret);
                                return true;
                            } catch (GeneralSecurityException var8) {
                                Logger.error("Unable to enable encryption for connection: "+var8.getMessage());
                                this.mcConnection.close(true);
                                return false;
                            }
                        }).get()) {
                            if(Config.getBoolean("log.auth-yggdrasil")) {
                                if (playerProfile == null) {
                                    Logger.info("Player " + username + " failed yggdrasil login.");
                                }else{
                                    Logger.info("Player " + username + " logged in with " + playerProfile.authentication + ".");
                                }
                            }
                            if (playerProfile == null) { // If authentication failed
                                LoginSession session = LoginSession.getSession(username);
                                if (Config.getBoolean("authentication.yggdrasil.password-auth-when-failed") && !session.isEnforcePrimaryMethod()) {
                                    session.setVerifyPassword(true);
                                    mcConnection.getChannel().eventLoop().submit(() -> {
                                        try{
                                            this.mcConnection.setActiveSessionHandler(StateRegistry.LOGIN,
                                                    (AuthSessionHandler) authSessionHandler_allArgsConstructor.invoke(
                                                            this.server, inbound, new GameProfile(
                                                                    UuidUtils.generateOfflinePlayerUuid(login.getUsername()),
                                                                    login.getUsername(),
                                                                    new ArrayList<>())
                                                            , false)
                                            );
                                        } catch (Throwable e) {
                                            throw new RuntimeException(e);
                                        }
                                    });
                                } else {
                                    this.inbound.disconnect(Message.getMessage("authentication.invalid-session").toComponent());
                                }
                                return;
                            }
                            mcConnection.getChannel().eventLoop().submit(() -> {
                                try {
                                    this.mcConnection.setActiveSessionHandler(StateRegistry.LOGIN,
                                            (AuthSessionHandler) authSessionHandler_allArgsConstructor.invoke(
                                                    this.server, inbound, new GameProfile(
                                                            UuidUtils.generateOfflinePlayerUuid(login.getUsername()),
                                                            login.getUsername(),
                                                            new ArrayList<>())
                                                    , true)
                                    );
                                } catch (Throwable e) {
                                    throw new RuntimeException(e);
                                }
                            }).get();
                        }
                    } catch (Throwable e) {
                        Logger.error("An exception occurred while processing validation results. "+e.getMessage());
                        if (encrypted) {
                            inbound.disconnect(Message.getMessage("sessionhandler.internal-error").toComponent());
                        }
                        mcConnection.close(true);
                    }
                }).schedule();
            } catch (GeneralSecurityException var9) {
                Logger.error("Unable to enable encryption. " + var9.getMessage());
                this.mcConnection.close(true);
            }
        } catch(Exception e) {
            Logger.error("An exception occurred while processing encryption response. " + e.getMessage());
            e.printStackTrace();
            this.mcConnection.close(true);
        }
    }

    private EncryptionRequestPacket generateEncryptionRequest() {
        byte[] verify = new byte[4];
        ThreadLocalRandom.current().nextBytes(verify);
        EncryptionRequestPacket request = new EncryptionRequestPacket();
        request.setPublicKey(this.server.getServerKeyPair().getPublic().getEncoded());
        request.setVerifyToken(verify);
        return request;
    }
}
