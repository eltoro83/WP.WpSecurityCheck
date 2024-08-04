<?php
require_once plugin_dir_path(__FILE__) . 'class-version-check.php';
require_once plugin_dir_path(__FILE__) . 'class-main-plugin.php';
class SecurityCheck {

    public static function get_security_status() {
        check_ajax_referer('wp_security_check_nonce', 'nonce');
    
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }
    
        $checks = self::run_security_checks();
        error_log('Security checks result: ' . print_r($checks, true));
    
        $total_checks = count($checks);
        $passed_checks = count(array_filter($checks, function($check) {
            return $check['status'] === true;
        }));
    
        $score = $total_checks > 0 ? round(($passed_checks / $total_checks) * 100) : 0;
        error_log('Calculated security score: ' . $score);
    
        $response_data = [
            'score' => $score,
            'checks' => $checks
        ];
        error_log('Full response data: ' . json_encode($response_data));
    
        wp_send_json_success($response_data);
    }

    public static function run_security_checks() {
        $results = array(
            'wp_version' => self::check_wordpress_version(),
            'plugins' => self::check_outdated_plugins(),
            'themes' => self::check_outdated_themes(),
            'debug_mode' => self::check_debug_mode(),
            'file_permissions' => self::check_file_permissions(),
            'admin_usernames' => self::check_admin_usernames()
        );
        $results['plugin_vulnerabilities'] = self::check_plugin_vulnerabilities();
        $results['suspicious_files'] = self::check_for_suspicious_files();
        
        error_log('Security check results: ' . print_r($results, true));
        update_option('wp_security_check_results', $results);
        
        return $results;
    }

    public static function get_last_security_check() {
        check_ajax_referer('wp_security_check_nonce', 'nonce');
    
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }
    
        $last_check = get_option('wp_security_check_results', null);
    
        if ($last_check) {
            wp_send_json_success($last_check);
        } else {
            wp_send_json_error('No previous security check found');
        }
    }

    public static function run_advanced_security_checks() {
        check_ajax_referer('wp_security_check_nonce', 'nonce');
    
        if (!current_user_can('manage_options')) {
            wp_die('Unauthorized');
        }
    
        $results = [
            'plugin_vulnerabilities' => self::check_plugin_vulnerabilities(),
            'suspicious_files' => self::check_for_suspicious_files()
        ];
    
        wp_send_json($results);
    }

    public static function check_plugin_vulnerabilities() {
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        $plugins = get_plugins();
        $vulnerable_plugins = [];
    
        foreach ($plugins as $plugin_file => $plugin_data) {
            $slug = explode('/', $plugin_file)[0];
            $version = $plugin_data['Version'];
    
            // API-Anfrage an WPScan Vulnerability Database
            $response = wp_remote_get("https://wpvulndb.com/api/v3/plugins/$slug");
    
            if (!is_wp_error($response) && wp_remote_retrieve_response_code($response) === 200) {
                $body = json_decode(wp_remote_retrieve_body($response), true);
                
                if (isset($body[$slug]['vulnerabilities'])) {
                    foreach ($body[$slug]['vulnerabilities'] as $vulnerability) {
                        if (version_compare($version, $vulnerability['fixed_in'], '<')) {
                            $vulnerable_plugins[] = $plugin_data['Name'] . " (Version $version)";
                            break;
                        }
                    }
                }
            }
        }
    
        return [
            'status' => empty($vulnerable_plugins),
            'message' => empty($vulnerable_plugins) ?
                "Keine bekannten Sicherheitslücken in installierten Plugins gefunden." :
                "Folgende Plugins haben bekannte Sicherheitslücken: " . implode(', ', $vulnerable_plugins)
        ];
    }

    public static function check_for_suspicious_files() {
        $suspicious_files = [];
        $malware_signatures = [
            'eval\s*\(\s*base64_decode',
            'base64_decode\s*\(\s*strrev',
            'gzinflate\s*\(\s*base64_decode',
            'eval\s*\(\s*gzinflate',
            'eval\s*\(\s*str_rot13',
            '<?=\s*`\$_`\s*?>',
            'preg_replace\s*\(\s*["\']/[^/]+/e',
            'assert\s*\(\s*\$_',
        ];
    
        $whitelist = [
            plugin_dir_path(__FILE__) . 'wp-security-check.php'
        ];
    
        $directories_to_scan = [
            ABSPATH,
            WP_CONTENT_DIR,
            WP_PLUGIN_DIR,
            get_theme_root()
        ];
    
        foreach ($directories_to_scan as $directory) {
            $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory));
            foreach ($iterator as $file) {
                if ($file->isFile() && $file->getExtension() === 'php' && !in_array($file->getPathname(), $whitelist)) {
                    $content = file_get_contents($file->getPathname());
                    foreach ($malware_signatures as $signature) {
                        if (preg_match('/' . $signature . '/i', $content, $matches, PREG_OFFSET_CAPTURE)) {
                            // Get the context around the match
                            $start = max(0, $matches[0][1] - 50);
                            $length = min(strlen($content) - $start, 100);
                            $context = substr($content, $start, $length);
                            
                            // Check if it's likely a false positive
                            if (!self::is_false_positive($context)) {
                                $suspicious_files[] = $file->getPathname() . " (Verdächtig: " . htmlspecialchars($matches[0][0]) . ")";
                                break;
                            }
                        }
                    }
                }
            }
        }
    
        return [
            'status' => empty($suspicious_files),
            'message' => empty($suspicious_files) ?
                "Keine verdächtigen Dateien gefunden." :
                "Folgende Dateien sind verdächtig und sollten überprüft werden: " . implode(', ', $suspicious_files)
        ];
    }

    private static function is_false_positive($context) {
        // Beispiele für Kontexte, die wahrscheinlich falsch-positiv sind
        $safe_contexts = [
            'function wordpress_evaluate',
            'class Base64Decoder',
            '* This is an example of malicious code',
            'function detect_malware',
        ];
    
        foreach ($safe_contexts as $safe_context) {
            if (stripos($context, $safe_context) !== false) {
                return true;
            }
        }
    
        return false;
    }
    private static function check_wordpress_version() {
        global $wp_version;
        $latest_wp_version = Versioncheck::get_latest_wordpress_version();
        return [
            'status' => version_compare($wp_version, $latest_wp_version, '>='),
            'message' => version_compare($wp_version, $latest_wp_version, '>=') ? 
                "WordPress ist auf dem neuesten Stand (Version $wp_version)." : 
                "WordPress sollte aktualisiert werden. Aktuelle Version: $wp_version, Neueste Version: $latest_wp_version"
        ];
    }
    private static function check_outdated_plugins() {
        $outdated_plugins = array();
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        $plugins = get_plugins();
        
        foreach ($plugins as $plugin_file => $plugin_data) {
            if (isset($plugin_data['Version'])) {
                // Korrigieren Sie die Extraktion des Plugin-Slugs
                $plugin_slug = dirname($plugin_file);
                if ($plugin_slug === '.') {
                    $plugin_slug = basename($plugin_file, '.php');
                }
                $latest_version = Versioncheck::get_latest_plugin_version($plugin_slug);
                if ($latest_version && version_compare($plugin_data['Version'], $latest_version, '<')) {
                    $outdated_plugins[] = $plugin_data['Name'];
                }
            }
        }
    
        return array(
            'status' => empty($outdated_plugins),
            'message' => empty($outdated_plugins) ?
                "Alle Plugins sind auf dem neuesten Stand." :
                "Folgende Plugins sollten aktualisiert werden: " . implode(', ', $outdated_plugins)
        );
    }
    private static function check_outdated_themes() {
        $outdated_themes = array();
        $themes = wp_get_themes();
        
        foreach ($themes as $theme_slug => $theme) {
            $latest_version = Versioncheck::get_latest_theme_version($theme_slug);
            if ($latest_version && version_compare($theme->get('Version'), $latest_version, '<')) {
                $outdated_themes[] = $theme->get('Name');
            }
        }
    
        return array(
            'status' => empty($outdated_themes),
            'message' => empty($outdated_themes) ?
                "Alle Themes sind auf dem neuesten Stand." :
                "Folgende Themes sollten aktualisiert werden: " . implode(', ', $outdated_themes)
        );
    }
    private static function check_debug_mode() {
        return array(
            'status' => !WP_DEBUG,
            'message' => WP_DEBUG ? 
                "Der Debug-Modus ist aktiviert. Dies sollte in Produktionsumgebungen deaktiviert werden." : 
                "Der Debug-Modus ist deaktiviert. Das ist gut für Produktionsumgebungen."
        );
    }
    private static function check_file_permissions() {
        $problematic_files = array();
        $important_files = array(
            ABSPATH . 'wp-config.php' => 0600,
            ABSPATH . '.htaccess' => 0644,
            ABSPATH . 'index.php' => 0644,
            ABSPATH . 'wp-admin/index.php' => 0644,
            ABSPATH . 'wp-includes/index.php' => 0644
        );
    
        foreach ($important_files as $file => $required_perms) {
            if (file_exists($file)) {
                $actual_perms = substr(sprintf('%o', fileperms($file)), -4);
                if ($actual_perms > $required_perms) {
                    $problematic_files[] = $file;
                }
            }
        }
    
        return array(
            'status' => empty($problematic_files),
            'message' => empty($problematic_files) ?
                "Alle überprüften Dateien haben angemessene Berechtigungen." :
                "Folgende Dateien haben zu offene Berechtigungen: " . implode(', ', $problematic_files)
        );
    }
    private static function check_admin_usernames() {
        $weak_usernames = array('admin', 'administrator', 'test', 'user', 'wp');
        $problematic_admins = array();
    
        $admin_users = get_users(array('role' => 'administrator'));
        foreach ($admin_users as $user) {
            if (in_array(strtolower($user->user_login), $weak_usernames)) {
                $problematic_admins[] = $user->user_login;
            }
        }
    
        return array(
            'status' => empty($problematic_admins),
            'message' => empty($problematic_admins) ?
                "Alle Admin-Benutzernamen sind stark." :
                "Folgende Admin-Benutzernamen sind schwach und sollten geändert werden: " . implode(', ', $problematic_admins)
        );
    }
}
?>
