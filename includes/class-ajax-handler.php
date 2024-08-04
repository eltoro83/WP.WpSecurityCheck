<?php

class AjaxHandler {

    public function __construct() {
        add_action('wp_ajax_get_security_status', array('SecurityCheck', 'get_security_status'));
        add_action('wp_ajax_run_security_checks', array('SecurityCheck', 'run_security_checks'));
        add_action('wp_ajax_get_last_security_check', array('SecurityCheck', 'get_last_security_check'));
        add_action('wp_ajax_create_backup', array('Backup', 'ajax_create_backup'));
        add_action('wp_ajax_optimize_database', array('DatabaseOptimization', 'ajax_optimize_database'));
    }
}
?>
