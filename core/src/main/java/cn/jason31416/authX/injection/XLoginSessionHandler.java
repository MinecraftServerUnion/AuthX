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
public class XLoginSessionHandler {
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
    private static MethodHandle authSessionHandler_constructor;
    private static Class<?>[] authSessionHandler_constructorParamTypes;

    private final InitialLoginSessionHandler initialLoginSessionHandler;
    private final MinecraftConnection mcConnection;
    private final LoginInboundConnection inbound;
    private boolean encrypted = false;
    private final VelocityServer server;
    private ServerLoginPacket login;
    private byte[] verify;

    public XLoginSessionHandler(InitialLoginSessionHandler initialLoginSessionHandler) {
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

        // Velocity internals change frequently; prefer signature-based matching with a name fallback.
        try {
            assertStateMethod = lookup.unreflect(ReflectionUtil.handleAccessible(
                    initialLoginSessionHandlerAccessor.findFirstMethodByName(true, "assertState")
            ));
        } catch (NoSuchMethodException ignored) {
            assertStateMethod = lookup.unreflect(ReflectionUtil.handleAccessible(
                    initialLoginSessionHandlerAccessor.findFirstMethod(true,
                            m -> m.getReturnType() == void.class
                                    && m.getParameterCount() == 1
                                    && m.getParameterTypes()[0].equals(loginStateEnum),
                            "InitialLoginSessionHandler assertState-like method not found")
            ));
        }

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


        // AuthSessionHandler constructor signature is not stable across Velocity versions (3.4 -> 3.5 changed).
// We match by a stable prefix: (VelocityServer, LoginInboundConnection, GameProfile, boolean, ...optional)
        java.lang.reflect.Constructor<?> bestCtor = null;
        for (java.lang.reflect.Constructor<?> c : AuthSessionHandler.class.getDeclaredConstructors()) {
            Class<?>[] p = c.getParameterTypes();
            if (p.length >= 4
                    && p[0] == VelocityServer.class
                    && p[1] == LoginInboundConnection.class
                    && p[2] == GameProfile.class
                    && p[3] == boolean.class) {
                if (bestCtor == null || p.length < bestCtor.getParameterTypes().length) {
                    bestCtor = c; // prefer the shortest matching ctor
                }
            }
        }
        if (bestCtor == null) {
            throw new NoSuchMethodException("AuthSessionHandler ctor not found (prefix match failed)");
        }
        bestCtor = ReflectionUtil.handleAccessible(bestCtor);
        authSessionHandler_constructor = lookup.unreflectConstructor(bestCtor);
        authSessionHandler_constructorParamTypes = bestCtor.getParameterTypes();
    }

    private void initValues() throws Throwable {
        this.login = (ServerLoginPacket) getLoginField.invoke(initialLoginSessionHandler);
        this.verify = (byte[]) getVerifyField.invoke(initialLoginSessionHandler);
    }

    private static Object defaultValue(Class<?> type) {
        // For optional extra constructor params: primitives get zero/false, references get null.
        if (!type.isPrimitive()) return null;
        if (type == boolean.class) return false;
        if (type == byte.class) return (byte) 0;
        if (type == short.class) return (short) 0;
        if (type == int.class) return 0;
        if (type == long.class) return 0L;
        if (type == float.class) return 0.0f;
        if (type == double.class) return 0.0d;
        if (type == char.class) return (char) 0;
        return null;
    }

    private AuthSessionHandler newAuthSessionHandler(LoginInboundConnection inbound, GameProfile profile, boolean onlineMode) throws Throwable {
        if (authSessionHandler_constructor == null || authSessionHandler_constructorParamTypes == null) {
            throw new IllegalStateException("XLoginSessionHandler not initialized (call XLoginSessionHandler.init())");
        }

        Object[] args = new Object[authSessionHandler_constructorParamTypes.length];
        args[0] = this.server;
        args[1] = inbound;
        args[2] = profile;
        args[3] = onlineMode;

        // Fill any extra params with safe defaults (null for refs, 0 for primitives).
        for (int i = 4; i < args.length; i++) {
            args[i] = defaultValue(authSessionHandler_constructorParamTypes[i]);
        }

        return (AuthSessionHandler) authSessionHandler_constructor.invokeWithArguments(args);
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
                                                    newAuthSessionHandler(
                                                            inbound, new GameProfile(
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
                                    Message disconnectMessage = session.getDisconnectMessage() == null
                                            ? Message.getMessage("auth.invalid-session")
                                            : session.getDisconnectMessage();
                                    this.inbound.disconnect(disconnectMessage.toComponent());
                                }
                                return;
                            }
                            mcConnection.getChannel().eventLoop().submit(() -> {
                                try {
                                    this.mcConnection.setActiveSessionHandler(StateRegistry.LOGIN,
                                            newAuthSessionHandler(
                                                    inbound, new GameProfile(
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
