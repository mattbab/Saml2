namespace Sustainsys.Saml2
{
    /**
     * Used to persist StoredRequestState between SignIn and Acs requests
     */
    public interface IRequestStateStore
    {
        /**
         * Saves the request state
         */
        void SetState(string key, StoredRequestState state);

        /**
         * Retrieves the stored request state based on the key provided. Returns null if the state cannot be found.
         */
        StoredRequestState GetState(string key);
    }
}
