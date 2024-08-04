<?php
class WP_Security_Check {

    public function __construct() {
        register_activation_hook(__FILE__, array($this, 'activate'));
        register_deactivation_hook(__FILE__, array($this, 'deactivate'));

        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_scripts'));
        add_action('init', array($this, 'init'));
        //add_action('wp_ajax_create_backup', array('Backup', 'create_backup'));
        add_action('wp_ajax_run_advanced_security_checks', array('SecurityCheck', 'run_advanced_security_checks'));
    }

    public function activate() {
        if (version_compare(get_bloginfo('version'), '5.0', '<')) {
            wp_die('Dieses Plugin erfordert WordPress Version 5.0 oder höher.');
            
        }

        $default_results = array(
            'last_check' => 0,
            'wp_version' => array('status' => false, 'message' => ''),
            'plugins' => array('status' => false, 'message' => ''),
            'themes' => array('status' => false, 'message' => ''),
            'debug_mode' => array('status' => false, 'message' => ''),
            'file_permissions' => array('status' => false, 'message' => ''),
            'admin_usernames' => array('status' => false, 'message' => '')
        );
        add_option('wp_security_check_results', $default_results);

        if (!wp_next_scheduled('wp_security_check_daily')) {
            wp_schedule_event(time(), 'daily', 'wp_security_check_daily');
        }

        $upload_dir = wp_upload_dir();
        $log_dir = $upload_dir['basedir'] . '/wp-security-check-logs';
        if (!file_exists($log_dir)) {
            wp_mkdir_p($log_dir);
        }

        DatabaseOptimization::set_log_file($log_dir . '/wp-security-check.log');

        $this->log('Plugin aktiviert');
        $this->create_backup();
        $this->create_htaccess_rules();
        $this->optimize_database();
        //$this->schedule_backup();
    }

    public function deactivate() {
        $this->log('Plugin deaktiviert');
        wp_clear_scheduled_hook('wp_security_check_daily');
        wp_clear_scheduled_hook('wp_security_check_backup');
    }

    public function add_admin_menu() {
        add_menu_page(
            'WP-Sicherheitsprüfung',
            'Sicherheitsprüfung',
            'manage_options',
            'wp-security-check',
            array($this, 'admin_page'),
            'dashicons-shield',
            100
        );
    }

    public function admin_page() {
        if (!current_user_can('manage_options')) {
            wp_die('Sie haben nicht die erforderlichen Berechtigungen, um diese Seite anzuzeigen.');
        }
    
        ?>
        <div class="wrap">
            <h1>WordPress Sicherheitsprüfung Dashboard</h1>
    
            <div id="security-dashboard">
                <div class="security-summary">
                    <h2>Sicherheitszusammenfassung</h2>
                    <canvas id="security-score-chart" width="300" height="300"></canvas>
                </div>
    
                <div class="security-details">
                    <h2>Detaillierte Sicherheitsprüfungen</h2>
                    <div id="security-checks-table"></div>
                </div>
    
                <div class="security-actions">
                    <h2>Sicherheitsaktionen</h2>
                    <button id="run-security-checks" class="button button-primary">Sicherheitsprüfungen durchführen</button>
                    <button id="create-backup" class="button button-secondary">Backup erstellen</button>
                    <div id="backup-result" style="margin-top: 20px;"></div>
                    <button id="optimize-database" class="button button-secondary">Datenbank optimieren</button>
                    <div id="optimize-result" style="margin-top: 20px;"></div>
                </div>
            </div>
        </div>
        <?php
    }

    public function enqueue_admin_scripts($hook) {
        if ($hook != 'toplevel_page_wp-security-check') {
            return;
        }

        wp_enqueue_style('wp-security-check-admin', plugins_url('../assets/css/admin.css', __FILE__), array(), '1.0');
        wp_enqueue_script('chart-js', 'https://cdn.jsdelivr.net/npm/chart.js', array(), '3.7.0', true);
        wp_enqueue_script('wp-security-check-admin', plugins_url('../assets/js/admin.js', __FILE__), array('jquery', 'chart-js'), '1.0', true);
        wp_localize_script('wp-security-check-admin', 'wpSecurityCheck', array(
            'ajax_url' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('wp_security_check_nonce')
        ));
    }

    public function init() {
        new AjaxHandler();
    }

    public function send_email_notification($results) {
        $to = get_option('admin_email');
        $subject = 'WordPress Sicherheitsbericht - ' . get_bloginfo('name');
        
        $message = "<!DOCTYPE html>
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; }
                .status-ok { color: green; }
                .status-error { color: red; }
            </style>
        </head>
        <body>
            <h2>WordPress Sicherheitsbericht</h2>
            <p>Hier ist der aktuelle Sicherheitsstatus Ihrer Website:</p>
            <table>
                <tr>
                    <th>Prüfung</th>
                    <th>Status</th>
                    <th>Details</th>
                </tr>";
    
        foreach ($results as $check => $result) {
            $status_class = $result['status'] ? 'status-ok' : 'status-error';
            $status_text = $result['status'] ? 'OK' : 'Fehler';
            $message .= "<tr>
                <td>" . ucfirst(str_replace('_', ' ', $check)) . "</td>
                <td class='$status_class'>$status_text</td>
                <td>{$result['message']}</td>
            </tr>";
        }
    
        $message .= "</table>
            <p>Bitte überprüfen Sie die Ergebnisse und ergreifen Sie gegebenenfalls Maßnahmen.</p>
        </body>
        </html>";
    
        $headers = array('Content-Type: text/html; charset=UTF-8');
    
        wp_mail($to, $subject, $message, $headers);
    }

    public function register_settings() {
        register_setting('wp_security_check_options', 'wp_security_check_settings', array($this, 'sanitize_settings'));
        add_settings_section('wp_security_check_main', 'Haupteinstellungen', array($this, 'settings_section_callback'), 'wp-security-check');
        add_settings_field(
            'notification_frequency',
            'Benachrichtigungshäufigkeit',
            array($this, 'notification_frequency_callback'),
            'wp-security-check',
            'wp_security_check_main'
        );
        add_settings_field(
            'email_notifications',
            'E-Mail-Benachrichtigungen',
            array($this, 'email_notifications_callback'),
            'wp-security-check',
            'wp_security_check_main'
        );
        add_settings_field('admin_email', 'Admin E-Mail', array($this, 'admin_email_callback'), 'wp-security-check', 'wp_security_check_main');
        //add_settings_field('two_factor_auth', 'Zwei-Faktor-Authentifizierung', array($this, 'two_factor_auth_callback'), 'wp-security-check', 'wp_security_check_main');
        add_settings_field('backup_frequency', 'Backup-Häufigkeit', array($this, 'backup_frequency_callback'), 'wp-security-check', 'wp_security_check_main');
    }

    public function settings_section_callback() {
        echo '<p>Konfigurieren Sie hier die Haupteinstellungen des Sicherheits-Plugins.</p>';
    }

    public function email_notifications_callback() {
        $value = isset($this->settings['email_notifications']) ? self::settings['email_notifications'] : false;
        echo '<input type="checkbox" name="wp_security_check_settings[email_notifications]" value="1" ' . checked(1, $value, false) . '/>';
        echo '<p class="description">Aktivieren Sie diese Option, um tägliche Sicherheitsberichte per E-Mail zu erhalten.</p>';
    }

    public function admin_email_callback() {
        $value = isset($this->settings['admin_email']) ? self::settings['admin_email'] : get_option('admin_email');
        echo '<input type="email" name="wp_security_check_settings[admin_email]" value="' . esc_attr($value) . '" />';
        echo '<p class="description">Geben Sie die E-Mail-Adresse ein, an die Sicherheitsberichte gesendet werden sollen.</p>';
    }

    public function two_factor_auth_callback() {
        $value = isset($this->settings['two_factor_auth']) ? $this->settings['two_factor_auth'] : false;
        echo '<input type="checkbox" name="wp_security_check_settings[two_factor_auth]" value="1" ' . checked(1, $value, false) . '/>';
        echo '<p class="description">Aktivieren Sie die Zwei-Faktor-Authentifizierung für Administrator-Konten.</p>';
    }

    public function backup_frequency_callback() {
        $value = isset($this->settings['backup_frequency']) ? $this->settings['backup_frequency'] : 'daily';
        $options = array(
            'hourly' => 'Stündlich',
            'daily' => 'Täglich',
            'weekly' => 'Wöchentlich'
        );
        echo '<select name="wp_security_check_settings[backup_frequency]">';
        foreach ($options as $key => $label) {
            echo '<option value="' . $key . '" ' . selected($value, $key, false) . '>' . $label . '</option>';
        }
        echo '</select>';
        echo '<p class="description">Wählen Sie die Häufigkeit für automatische Backups.</p>';
    }
    public function sanitize_settings($input) {
        $sanitized_input = array();
        $sanitized_input['email_notifications'] = isset($input['email_notifications']) ? (bool)$input['email_notifications'] : false;
        $sanitized_input['admin_email'] = sanitize_email($input['admin_email']);
        $sanitized_input['two_factor_auth'] = isset($input['two_factor_auth']) ? (bool)$input['two_factor_auth'] : false;
        return $sanitized_input;
    }
    public function run_scheduled_security_checks() {
        $results = array(
            'last_check' => time(),
            'wp_version' => $this->check_wordpress_version(),
            'plugins' => $this->check_outdated_plugins(),
            'themes' => $this->check_outdated_themes(),
            'debug_mode' => $this->check_debug_mode(),
            'file_permissions' => $this->check_file_permissions(),
            'admin_usernames' => $this->check_admin_usernames()
        );

        update_option('wp_security_check_results', $results);

        $this->send_email_notification($results);
    } 
    private function log($message) {
        if (self::log_file) {
            $timestamp = date('Y-m-d H:i:s');
            file_put_contents($this->log_file, "[$timestamp] $message\n", FILE_APPEND);
        }
    }
    public function login_error_message($error) {
        if (isset($_GET['two_factor_error'])) {
            $error = '<strong>FEHLER</strong>: Ungültiger Zwei-Faktor-Authentifizierungscode.';
        }
        return $error;
    }
    public function display_admin_notices() {
        // Prüfen, ob wir uns im Dashboard befinden und nicht auf der Plugin-Seite
        $screen = get_current_screen();
        if ($screen->base !== 'dashboard' || $_GET['page'] === 'wp-security-check') {
            return;
        }
    
        $security_status = get_option('wp_security_check_results', array());
        
        if (empty($security_status)) {
            return;
        }
    
        $critical_issues = array();
        foreach ($security_status as $check => $result) {
            if ($result['status'] === false) {
                $critical_issues[] = $result['message'];
            }
        }
    
        if (!empty($critical_issues)) {
            echo '<div class="notice notice-error is-dismissible">';
            echo '<p><strong>Sicherheitswarnung:</strong> Es wurden kritische Probleme erkannt:</p>';
            echo '<ul>';
            foreach ($critical_issues as $issue) {
                echo "<li>$issue</li>";
            }
            echo '</ul>';
            echo '<p>Besuchen Sie die <a href="' . admin_url('admin.php?page=wp-security-check') . '">Sicherheitsprüfung-Seite</a> für weitere Details.</p>';
            echo '</div>';
        }
    }
}
?>
