<?php
/**
 * Plugin Name: WP-Sicherheitsprüfung
 * Plugin URI: https://wp-security.pascalstier.de
 * Description: Ein kleines erweitertes Plugin zur Überprüfung und Verbesserung der WordPress-Sicherheit
 * Version: 1.0
 * Author: Pascal Stier
 * Author URI: https://pascalstier.de
 */

 defined('ABSPATH') or die('No script kiddies please!');

require_once plugin_dir_path(__FILE__) . 'includes/class-security-check.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-backup.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-database-optimization.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-two-factor-auth.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-version-check.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-ajax-handler.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-main-plugin.php';

// Initialize the plugin
new WP_Security_Check();
//new AjaxHandler();

// Set the log file path
$upload_dir = wp_upload_dir();
$log_dir = $upload_dir['basedir'] . '/wp-security-check-logs';
if (!file_exists($log_dir)) {
    wp_mkdir_p($log_dir);
}
DatabaseOptimization::set_log_file($log_dir . '/wp-security-check.log');
Backup::set_log_file($log_dir . '/wp-security-check.log');
?>