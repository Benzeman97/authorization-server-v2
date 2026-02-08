@Configuration
@EnableWebSecurity
public class WebSecurityConfiguration {

   private final UserDetailsService userDetailsService;
    private final AuthenticationEntryPoint authEntryPoint;

    /**
     * Constructor injection (same as before)
     */
    public WebSecurityConfiguration(UserDetailsService userDetailsService, 
                                   AuthenticationEntryPoint authEntryPoint) {
        this.userDetailsService = userDetailsService;
        this.authEntryPoint = authEntryPoint;
    }

  /* NEW CODE (4.0.2):
     * Uses lambda-based configuration and SecurityFilterChain bean.
     * 
     * IMPORTANT: Use @Order(3) to ensure this runs AFTER AuthorizationServerConfig
     * - Order(1): OAuth2 Authorization Server endpoints
     * - Order(2): Default security (form login)
     * - Order(3): Your API security (this configuration)
     */

    @Bean
    @Order(3)
    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            // Enable CORS
            // OLD: .cors().and()
            // NEW: Lambda-based with defaults
            .cors(Customizer.withDefaults())
            
            // Disable CSRF (for stateless REST API)
            // OLD: .csrf().disable()
            // NEW: Lambda syntax
            .csrf(csrf -> csrf.disable())
            
            // Custom authentication entry point
            // OLD: .exceptionHandling().authenticationEntryPoint(authEntryPoint)
            // NEW: Lambda configuration
            .exceptionHandling(exception -> exception
                .authenticationEntryPoint(authEntryPoint)
            )
            
            // Stateless session (no HttpSession created)
            // OLD: .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            // NEW: Lambda syntax
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            
            // Require authentication for all requests
            // OLD: .authorizeRequests().anyRequest().authenticated()
            // NEW: authorizeHttpRequests (method renamed in Spring Security 6.x)
            .authorizeHttpRequests(authorize -> authorize
                .anyRequest().authenticated()
            );
        
        // CRITICAL: Must return http.build()
        return http.build();
    }

     /* 
     * NEW CODE (4.0.2):
     * Exposed as a public bean instead of private method.
     * This allows Spring to manage it and inject it where needed.
     */
    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService);
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;
    }

     /* 
     * NEW CODE (4.0.2):
     * Create AuthenticationManager explicitly using ProviderManager.
     * 
     * WHY THIS IS BETTER:
     * - More transparent (you can see exactly what's being configured)
     * - Easier to customize (add multiple providers, configure parent manager, etc.)
     * - No hidden magic from super.authenticationManager()
     * 
     * NOTE: This AuthenticationManager is used by your Authorization Server
     * for the password grant type and other authentication needs.
     */
  
    @Bean
    public AuthenticationManager authenticationManager(DaoAuthenticationProvider authenticationProvider) {
        // ProviderManager is the standard implementation of AuthenticationManager
        // It delegates to a list of AuthenticationProvider instances
        return new ProviderManager(authenticationProvider);
    }

    /* DelegatingPasswordEncoder supports multiple encoding formats:
     * - {bcrypt}$2a$10$... - BCrypt (default for new passwords)
     * - {pbkdf2}... - PBKDF2
     * - {scrypt}... - SCrypt
     * - {sha256}... - SHA-256
     * - {noop}plain-text - No encoding (NOT RECOMMENDED)
     * 
     * When you encode a new password, it uses BCrypt and prefixes it with {bcrypt}.
     * When validating, it looks at the prefix to determine which encoder to use.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

     /**
     * OPTIONAL: CORS Configuration Source
     * 
     * If you need to customize CORS beyond the defaults, uncomment this:
     */
    /*
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        
        // Allow specific origins (change to your frontend URL)
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:3000", "http://localhost:4200"));
        
        // Allow specific HTTP methods
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        
        // Allow specific headers
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "Accept"));
        
        // Allow credentials (cookies, authorization headers)
        configuration.setAllowCredentials(true);
        
        // Cache preflight response for 1 hour
        configuration.setMaxAge(3600L);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
    
    // Then update your SecurityFilterChain:
    @Bean
    @Order(3)
    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            // ... rest of config
    }
    */
}
