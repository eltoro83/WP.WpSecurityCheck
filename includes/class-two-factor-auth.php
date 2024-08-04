<?php

class TwoFactorAuth {

    public function add_2fa_user_profile_fields($user) {
        if (in_array('administrator', $user->roles)) {
            $two_factor_enabled = get_user_meta($user->ID, 'two_factor_enabled', true);
            ?>
            <h3>Zwei-Faktor-Authentifizierung</h3>
            <table class="form-table">
                <tr>
                    <th><label for="two_factor_enabled">2FA aktivieren</label></th>
                    <td>
                        <input type="checkbox" name="two_factor_enabled" id="two_factor_enabled" value="1" <?php checked($two_factor_enabled, '1'); ?>>
                        <span class="description">Aktivieren Sie die Zwei-Faktor-Authentifizierung für zusätzliche Sicherheit.</span>
                    </td>
                </tr>
            </table>
            <?php
        }
    }

    public function save_2fa_user_profile_fields($user_id) {
        if (current_user_can('edit_user', $user_id)) {
            update_user_meta($user_id, 'two_factor_enabled', isset($_POST['two_factor_enabled']) ? '1' : '0');
        }
    }

    public function generate_2fa_code($user_id) {
        $code = wp_generate_password(6, false, false);
        $expiration = time() + (15 * 60); // Code ist 15 Minuten gültig
        update_user_meta($user_id, 'two_factor_code', $code);
        update_user_meta($user_id, 'two_factor_expiration', $expiration);
        return $code;
    }

    public function verify_2fa_code($user_id, $code) {
        $stored_code = get_user_meta($user_id, 'two_factor_code', true);
        $expiration = get_user_meta($user_id, 'two_factor_expiration', true);
        
        if ($code === $stored_code && time() < $expiration) {
            delete_user_meta($user_id, 'two_factor_code');
            delete_user_meta($user_id, 'two_factor_expiration');
            return true;
        }
        return false;
    }

    public function two_factor_auth($user, $username, $password) {
        if (!$user) {
            return $user;
        }
    
        if (in_array('administrator', $user->roles) && get_user_meta($user->ID, 'two_factor_enabled', true) === '1') {
            $code = $this->generate_2fa_code($user->ID);
            $to = $user->user_email;
            $subject = 'Ihr Zwei-Faktor-Authentifizierungscode';
            $message = "Ihr Code lautet: $code\n\nDieser Code ist 15 Minuten gültig.";
            wp_mail($to, $subject, $message);
    
            wp_redirect(admin_url('admin-post.php?action=two_factor_auth&user_id=' . $user->ID));
            exit;
        }
    
        return $user;
    }

    public function handle_2fa_form() {
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['two_factor_code'], $_POST['user_id'])) {
            $user_id = intval($_POST['user_id']);
            $code = sanitize_text_field($_POST['two_factor_code']);
    
            if ($this->verify_2fa_code($user_id, $code)) {
                wp_set_auth_cookie($user_id);
                wp_redirect(admin_url());
                exit;
            } else {
                wp_redirect(wp_login_url() . '?two_factor_error=1');
                exit;
            }
        }
    
        $user_id = isset($_GET['user_id']) ? intval($_GET['user_id']) : 0;
        $this->render_2fa_form($user_id);
    }
    private function render_2fa_form($user_id) {
        ?>
        <!DOCTYPE html>
        <html>
        <head>
            <title>Zwei-Faktor-Authentifizierung</title>
            <?php wp_head(); ?>
        </head>
        <body>
            <div style="max-width: 400px; margin: 100px auto; padding: 20px; border: 1px solid #ddd; border-radius: 5px;">
                <h2>Zwei-Faktor-Authentifizierung</h2>
                <p>Bitte geben Sie den Code ein, der an Ihre E-Mail-Adresse gesendet wurde.</p>
                <form method="post" action="">
                    <input type="hidden" name="user_id" value="<?php echo esc_attr($user_id); ?>">
                    <input type="text" name="two_factor_code" required style="width: 100%; padding: 10px; margin-bottom: 10px;">
                    <input type="submit" value="Verifizieren" style="width: 100%; padding: 10px; background-color: #0085ba; color: #fff; border: none; cursor: pointer;">
                </form>
            </div>
            <?php wp_footer(); ?>
        </body>
        </html>
        <?php
    }
}
?>
