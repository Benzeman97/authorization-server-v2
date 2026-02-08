

@ConfigurationProperties(prefix = "security")
@Validated
public class SecurityProperties {

   @NotNull(message = "JWT configuration is required")
   private JwtProperties jwt;

   public JwtProperties getJwt() {
        return jwt;
    }
    
    public void setJwt(JwtProperties jwt) {
        this.jwt = jwt;
    }
    
   public static class JwtProperties {

        @NotNull(message = "KeyStore location is required")
        private Resource keyStore;

        @NotNull(message = "KeyStore password is required")
        private String keyStorePassword;

        @NotNull(message = "Key pair alias is required")
        private String keyPairAlias;

        @NotNull(message = "Key pair password is required")
        private String keyPairPassword;

     public Resource getKeyStore() {
            return keyStore;
        }
        
        public void setKeyStore(Resource keyStore) {
            this.keyStore = keyStore;
        }
        
        public String getKeyStorePassword() {
            return keyStorePassword;
        }
        
        public void setKeyStorePassword(String keyStorePassword) {
            this.keyStorePassword = keyStorePassword;
        }
        
        public String getKeyPairAlias() {
            return keyPairAlias;
        }
        
        public void setKeyPairAlias(String keyPairAlias) {
            this.keyPairAlias = keyPairAlias;
        }
        
        public String getKeyPairPassword() {
            return keyPairPassword;
        }
        
        public void setKeyPairPassword(String keyPairPassword) {
            this.keyPairPassword = keyPairPassword;
        }
     
     }

}
