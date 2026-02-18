package cn.jason31416.authX.hook;

import org.geysermc.floodgate.api.FloodgateApi;

import java.util.UUID;

public class FloodgateHandler {
    public static boolean isFloodgatePlayer(UUID uuid){
        try {
            return FloodgateApi.getInstance().isFloodgatePlayer(uuid);
        }catch (Exception e){
            return false;
        }
    }
}
