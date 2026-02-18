package cn.jason31416.authx.api;

public interface AuthXApi {
    /**
     * Fetches an instance of the authenticator, which allows you to quickly perform actions such as authentication, registration, etc.
     * If you wish, you can set your own authenticator with the `getAuthenticator().setInstance()` method, but try to do it before server finishes initialization.
     * @return AbstractAuthenticator instance
     */
    AbstractAuthenticator getAuthenticator();

    /**
     * Fetches an instance of the Database Handler that allows you to directly modify AuthX's database.
     * @return DatabaseHandler instance
     */
    IDatabaseHandler getDatabaseHandler();

    /**
     * Fetches the current version string. Example: 'Beta 2.2'
     * @return Version string
     */
    String getVersion();

    ILoginSession getPlayerData(String username);
}
