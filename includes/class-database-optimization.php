<?php

class DatabaseOptimization {

    private static $log_file;

    public static function set_log_file($file_path) {
        self::$log_file = $file_path;
    }

    public static function ajax_optimize_database() {
        check_ajax_referer('wp_security_check_nonce', 'nonce');
    
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => 'Unzureichende Berechtigungen.'));
        }
    
        $optimized_tables = self::optimize_database();
    
        if ($optimized_tables !== false) {
            wp_send_json_success(array(
                'message' => 'Datenbank wurde erfolgreich optimiert.',
                'tables' => $optimized_tables
            ));
        } else {
            wp_send_json_error(array('message' => 'Datenbank konnte nicht optimiert werden.'));
        }
    }
    public static function optimize_database() {
        global $wpdb;
        
        $tables = $wpdb->get_results("SHOW TABLES", ARRAY_N);
        $optimized = 0;
        
        foreach ($tables as $table) {
            if ($wpdb->query("OPTIMIZE TABLE $table[0]")) {
                $optimized++;
            }
        }
        
        self::log("Datenbank-Optimierung abgeschlossen. $optimized Tabellen optimiert.");
        return $optimized;
    }
    private static function log($message) {
        if (self::$log_file) {
            $timestamp = date('Y-m-d H:i:s');
            file_put_contents(self::$log_file, "[$timestamp] $message\n", FILE_APPEND);
        }
    }
}
?>
