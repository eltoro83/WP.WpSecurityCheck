<?php

class VersionCheck {

    public static function get_latest_theme_version($theme_slug) {
        if (!function_exists('themes_api')) {
            require_once(ABSPATH . 'wp-admin/includes/theme.php');
        }

        $args = array(
            'slug' => $theme_slug,
            'fields' => array('version' => true)
        );

        $response = themes_api('theme_information', $args);

        if (is_wp_error($response)) {
            return null;
        }

        return $response->version;
    }

    public static function get_latest_wordpress_version() {
        $response = wp_remote_get('https://api.wordpress.org/core/version-check/1.7/');

        if (is_wp_error($response)) {
            return null;
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        if (isset($data['offers'][0]['version'])) {
            return $data['offers'][0]['version'];
        }

        return null;
    }

    public static function get_latest_plugin_version($plugin_slug) {
        if (!function_exists('plugins_api')) {
            require_once(ABSPATH . 'wp-admin/includes/plugin-install.php');
        }

        $args = array(
            'slug' => $plugin_slug,
            'fields' => array('version' => true)
        );

        $response = plugins_api('plugin_information', $args);

        if (is_wp_error($response)) {
            return null;
        }

        return isset($response->version) ? $response->version : null;
    }
}
?>
