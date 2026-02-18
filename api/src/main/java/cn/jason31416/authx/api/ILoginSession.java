package cn.jason31416.authx.api;

public interface ILoginSession {
    String getUsername();

    java.util.UUID getUuid();

    String getAuthMethod();
}
