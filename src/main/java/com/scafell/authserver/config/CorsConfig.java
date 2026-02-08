
 /* 
 * NEW APPROACH (4.0.2):
 * - Uses CorsConfigurationSource (better integration with Spring Security)
 * - Explicitly defines all CORS settings
 * - More secure with specific origins
 * - Works seamlessly with WebSecurityConfiguration
 */
 package com.scafell.authserver.config;

 import org.springframework.context.annotation.Bean;
 import org.springframework.context.annotation.Configuration;
 import org.springframework.web.cors.CorsConfiguration;
 import org.springframework.web.cors.CorsConfigurationSource;
 import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

 import java.util.Arrays;

 @Configuration
public class CorsConfig {

    /**
     * CORS Configuration Source
     * 
     * This bean is automatically picked up by Spring Security when you use:
     * http.cors(Customizer.withDefaults())
     * 
     * IMPORTANT SECURITY NOTES:
     * 1. NEVER use allowedOrigins("*") with allowCredentials(true)
     * 2. Always specify exact origins in production
     * 3. Include OPTIONS method for preflight requests
     * 4. Use maxAge to reduce preflight overhead
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        
        // ========================================
        // ALLOWED ORIGINS
        // ========================================
        //  CRITICAL: Replace with your actual frontend URLs
        // 
        // Development:
        configuration.setAllowedOrigins(Arrays.asList(
            "http://localhost:3000",      // React default dev server
            "http://localhost:4200",      // Angular default dev server
            "http://localhost:8080",      // Your client application
            "http://127.0.0.1:3000",      // Alternative localhost
            "http://127.0.0.1:4200"
        ));
        
        // Production (uncomment and modify):
        // configuration.setAllowedOrigins(Arrays.asList(
        //     "https://yourdomain.com",
        //     "https://www.yourdomain.com",
        //     "https://app.yourdomain.com"
        // ));
        
        //  NEVER do this in production:
        // configuration.setAllowedOrigins(Arrays.asList("*"));  // Security risk!
        
        // ========================================
        // ALLOWED METHODS
        // ========================================
        // Include all HTTP methods your API uses
        configuration.setAllowedMethods(Arrays.asList(
            "GET",      // Read operations
            "POST",     // Create operations
            "PUT",      // Update operations (full replacement)
            "DELETE",   // Delete operations
            "PATCH",    // Update operations (partial update)
            "OPTIONS"   // CRITICAL: Required for CORS preflight
        ));
        
        // Alternative: Allow all methods (less secure)
        // configuration.setAllowedMethods(Arrays.asList("*"));
        
        // ========================================
        // ALLOWED HEADERS
        // ========================================
        // Headers that clients can send in requests
        configuration.setAllowedHeaders(Arrays.asList(
            "Authorization",      // For JWT tokens, Basic auth, etc.
            "Content-Type",       // For JSON, form data, etc.
            "Accept",            // Accept header
            "X-Requested-With",  // AJAX requests
            "Cache-Control",     // Cache control
            "Origin"             // Origin header
        ));
        
        // Alternative: Allow all headers (most permissive)
        // configuration.setAllowedHeaders(Arrays.asList("*"));
        
        // ========================================
        // EXPOSED HEADERS
        // ========================================
        // Headers that browsers can access in the response
        // By default, only these headers are exposed:
        //   - Cache-Control, Content-Language, Content-Type, 
        //     Expires, Last-Modified, Pragma
        // 
        // If you return custom headers (like Authorization with refresh tokens),
        // you need to expose them:
        configuration.setExposedHeaders(Arrays.asList(
            "Authorization",              // If you return tokens in headers
            "Access-Control-Allow-Origin",
            "Access-Control-Allow-Credentials"
        ));
        
        // ========================================
        // CREDENTIALS
        // ========================================
        // Allow cookies, authorization headers, and TLS client certificates
        // 
        // Set to TRUE if your frontend needs to send:
        // - Cookies (session cookies, CSRF tokens)
        // - Authorization headers (JWT tokens, Basic auth)
        // - Client certificates
        configuration.setAllowCredentials(true);
        
        //  NOTE: If allowCredentials is true, you CANNOT use allowedOrigins("*")
        // You must specify exact origins
        
        // ========================================
        // PREFLIGHT CACHE (maxAge)
        // ========================================
        // How long (in seconds) browsers can cache preflight responses
        // This reduces the number of OPTIONS requests
        // 
        // 3600 seconds = 1 hour (good balance between security and performance)
        configuration.setMaxAge(3600L);
        
        // Longer cache (use with caution):
        // configuration.setMaxAge(86400L);  // 24 hours
        
        // ========================================
        // APPLY CONFIGURATION
        // ========================================
        // Apply this configuration to all endpoints
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        
        // For different CORS rules on different endpoints:
        // source.registerCorsConfiguration("/api/public/**", publicConfig);
        // source.registerCorsConfiguration("/api/admin/**", adminConfig);
        
        return source;
    }
    
    /**
     * ALTERNATIVE APPROACH: Using WebMvcConfigurer
     * 
     * You can keep this if you prefer, but CorsConfigurationSource
     * is recommended for better Spring Security integration.
     * 
     * Uncomment if you want to use this approach instead:
     */
    /*
    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")
                    .allowedOrigins("http://localhost:3000", "http://localhost:4200")
                    .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH")
                    .allowedHeaders("*")
                    .allowCredentials(true)
                    .maxAge(3600);
            }
        };
    }
    */

}
