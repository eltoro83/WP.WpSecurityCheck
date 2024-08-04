<?php

class Htaccess {

    public static function create_htaccess_rules() {
        $htaccess_file = ABSPATH . '.htaccess';
        $rules = "
# Disable directory browsing
Options All -Indexes

# Protect wp-config.php
<files wp-config.php>
order allow,deny
deny from all
</files>

# Limit file uploads to 10MB
php_value upload_max_filesize 10M
php_value post_max_size 10M
";

        if (is_writable($htaccess_file)) {
            file_put_contents($htaccess_file, $rules, FILE_APPEND);
            error_log("Htaccess-Regeln erfolgreich hinzugefügt.");
        } else {
            error_log("Konnte Htaccess-Regeln nicht hinzufügen. Datei nicht beschreibbar.");
        }
    }
}
?>
