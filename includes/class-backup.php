<?php

class Backup {
    private static $log_file;

    public static function set_log_file($file_path) {
        self::$log_file = $file_path;
    }

    public static function create_backup() {
        $upload_dir = wp_upload_dir();
        $backup_dir = $upload_dir['basedir'] . '/wp-security-check-backups';

        if (!file_exists($backup_dir)) {
            wp_mkdir_p($backup_dir);
        }
        self::log("Hit");
        $date = current_time('Y-m-d-H-i-s');
        $backup_file = $backup_dir . '/backup-' . $date . '.zip';

        // Dateien sichern
        $files_to_backup = self::get_files_to_backup();
        $zip = new ZipArchive();
        if ($zip->open($backup_file, ZipArchive::CREATE) === TRUE) {
            foreach ($files_to_backup as $file) {
                if (is_file($file)) {
                    $zip->addFile($file, str_replace(ABSPATH, '', $file));
                } elseif (is_dir($file)) {
                    self::add_folder_to_zip($zip, $file);
                }
            }
            $zip->close();
        } else {
            self::log("Fehler beim Erstellen des Backups: Konnte ZIP-Datei nicht öffnen.");
            return false;
        }

        // Datenbank sichern
        $db_backup_file = $backup_dir . '/db-backup-' . $date . '.sql';
        if (!self::backup_database($db_backup_file)) {
            self::log("Fehler beim Erstellen des Datenbank-Backups.");
            return false;
        }

        // Datenbank-Backup zur ZIP-Datei hinzufügen
        $zip = new ZipArchive();
        if ($zip->open($backup_file) === TRUE) {
            $zip->addFile($db_backup_file, 'database.sql');
            $zip->close();
        }

        // Temporäre Datenbank-Backup-Datei löschen
        unlink($db_backup_file);

        self::log("Backup erfolgreich erstellt: $backup_file");
        return $backup_file;
    }
    
    public static function ajax_create_backup() {
        check_ajax_referer('wp_security_check_nonce', 'nonce');
    
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => 'Unzureichende Berechtigungen.'));
        }
    
        $backup_file = self::create_backup();
    
        if ($backup_file) {
            $upload_dir = wp_upload_dir();
            $backup_url = str_replace($upload_dir['basedir'], $upload_dir['baseurl'], $backup_file);
            wp_send_json_success(array(
                'message' => 'Backup wurde erfolgreich erstellt.',
                'file' => basename($backup_file),
                'path' => $backup_file,
                'url' => $backup_url
            ));
        } else {
            wp_send_json_error(array('message' => 'Backup konnte nicht erstellt werden.'));
        }
    }

    private static function backup_database($file) {
        global $wpdb;
    
        $tables = $wpdb->get_results('SHOW TABLES', ARRAY_N);
        $output = '';
    
        foreach ($tables as $table) {
            $table_name = $table[0];
            $result = $wpdb->get_results("SELECT * FROM {$table_name}", ARRAY_N);
            $row2 = $wpdb->get_row('SHOW CREATE TABLE ' . $table_name, ARRAY_N);
            $output .= "\n\n" . $row2[1] . ";\n\n";
    
            foreach ($result as $row) {
                $output .= 'INSERT INTO ' . $table_name . ' VALUES(';
                for ($j = 0; $j < count($row); $j++) {
                    $row[$j] = addslashes($row[$j]);
                    $row[$j] = str_replace("\n", "\\n", $row[$j]);
                    if (isset($row[$j])) {
                        $output .= '"' . $row[$j] . '"';
                    } else {
                        $output .= '""';
                    }
                    if ($j < (count($row) - 1)) {
                        $output .= ',';
                    }
                }
                $output .= ");\n";
            }
        }
    
        $handle = fopen($file, 'w+');
        fwrite($handle, $output);
        fclose($handle);
    
        return true;
    }

    private static function add_folder_to_zip($zip, $folder) {
        $folder = rtrim($folder, '/') . '/';
        $root_path = str_replace(ABSPATH, '', $folder);
        
        $files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($folder),
            RecursiveIteratorIterator::LEAVES_ONLY
        );
    
        foreach ($files as $name => $file) {
            if (!$file->isDir()) {
                $file_path = $file->getRealPath();
                $relative_path = $root_path . substr($file_path, strlen($folder));
                $zip->addFile($file_path, $relative_path);
            }
        }
    }

    private static function get_files_to_backup() {
        $files = array(
            ABSPATH . 'wp-config.php',
            ABSPATH . '.htaccess',
            WP_CONTENT_DIR . '/themes',
            WP_CONTENT_DIR . '/plugins',
            WP_CONTENT_DIR . '/uploads'
        );
        return apply_filters('wp_security_check_backup_files', $files);
    }

    private static function schedule_backup() {
        $frequency = isset(self::settings['backup_frequency']) ? self::settings['backup_frequency'] : 'daily';
        if (!wp_next_scheduled('wp_security_check_backup')) {
            wp_schedule_event(time(), $frequency, 'wp_security_check_backup');
        }
    }
    private static function log($message) {
        if (self::$log_file) {
            $timestamp = date('Y-m-d H:i:s');
            file_put_contents(self::$log_file, "[$timestamp] $message\n", FILE_APPEND);
        }
    }
}
?>
