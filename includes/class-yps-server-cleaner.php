<?php
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class YPS_Server_Cleaner {
    private $results = array();

    public function __construct() {
        add_action( 'admin_menu', array( $this, 'register_admin_page' ) );
        add_action( 'admin_init', array( $this, 'maybe_export_csv' ) );
        add_action( 'admin_init', array( $this, 'maybe_delete_file' ) );
        add_action( 'wp_login', array( $this, 'capture_login' ), 10, 1 );
    }

    public function register_admin_page() {
        add_management_page(
            __( 'Server Cleaner', 'server-cleaner' ),
            __( 'Server Cleaner', 'server-cleaner' ),
            'manage_options',
            'server-cleaner',
            array( $this, 'admin_page_html' )
        );
    }

    public function admin_page_html() {
        if ( ! current_user_can( 'manage_options' ) ) return;

        echo '<div class="wrap"><h1>Server Cleaner</h1>';
        echo '<p>Scan your site for duplicate, outdated, or suspicious files. Delete flagged items and monitor login activity.</p>';

        echo '<form method="post">';
        wp_nonce_field( 'server_cleaner_scan', 'server_cleaner_nonce' );
        submit_button( 'Scan Now', 'primary', 'scan_now' );
        echo '</form>';

        if ( isset($_POST['scan_now']) && check_admin_referer('server_cleaner_scan','server_cleaner_nonce') ) {
            $this->results = $this->run_scan();
            $this->render_results();
        }

        $this->render_login_activity();
        echo '</div>';
    }

    private function run_scan() {
        $results = array();
        $scan_dirs = array(WP_CONTENT_DIR.'/uploads', WP_CONTENT_DIR.'/plugins', WP_CONTENT_DIR.'/themes');
        $file_index = array();

        foreach ($scan_dirs as $dir) {
            if (!is_dir($dir)) continue;
            $rii = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS));

            foreach ($rii as $file) {
                if ($file->isDir()) continue;

                $filepath = $file->getPathname();
                $ext = strtolower(pathinfo($filepath, PATHINFO_EXTENSION));

                // Duplicate check
                $basename = basename($filepath);
                if (isset($file_index[$basename])) {
                    $results[$filepath] = 'Duplicate filename found in '.$file_index[$basename];
                } else {
                    $file_index[$basename] = $filepath;
                }

                // Suspicious: PHP in uploads
                if (strpos($filepath,'uploads')!==false && $ext==='php') {
                    $results[$filepath] = 'Suspicious: PHP file inside uploads folder';
                }

                // Suspicious patterns
                if ($ext==='php') {
                    $contents = @file_get_contents($filepath);
                    if ($contents && (strpos($contents,'base64_decode')!==false ||
                                      strpos($contents,'eval(')!==false ||
                                      strpos($contents,'gzinflate')!==false ||
                                      strpos($contents,'shell_exec')!==false)) {
                        $results[$filepath] = 'Potentially malicious code pattern found';
                    }
                }
            }
        }
        return $results;
    }

    private function render_results() {
        if (empty($this->results)) {
            echo '<p>No issues found. Your WordPress files look clean.</p>';
            return;
        }

        echo '<h2>Scan Results</h2><table class="widefat striped">';
        echo '<thead><tr><th>File</th><th>Reason</th><th>Action</th></tr></thead><tbody>';
        foreach ($this->results as $file=>$reason) {
            echo '<tr><td>'.esc_html($file).'</td><td>'.esc_html($reason).'</td><td>
                  <form method="post" style="display:inline;">'.
                  wp_nonce_field('server_cleaner_delete','server_cleaner_delete_nonce',true,false).'
                  <input type="hidden" name="delete_file" value="'.esc_attr($file).'">
                  <input type="submit" class="button delete-file" value="Delete" onclick="return confirm(\'Delete this file?\');">
                  </form></td></tr>';
        }
        echo '</tbody></table>';
        echo '<form method="post">'.wp_nonce_field('server_cleaner_export','server_cleaner_export_nonce').'<input type="submit" class="button" name="export_csv" value="Export to CSV"></form>';
    }

    public function maybe_export_csv() {
        if (isset($_POST['export_csv']) && check_admin_referer('server_cleaner_export','server_cleaner_export_nonce')) {
            header('Content-Type: text/csv');
            header('Content-Disposition: attachment;filename=server-cleaner-results.csv');
            $out=fopen('php://output','w');
            fputcsv($out,['File','Reason']);
            foreach ($this->results as $file=>$reason) fputcsv($out,[$file,$reason]);
            fclose($out);
            exit;
        }
    }

    public function maybe_delete_file() {
        if (isset($_POST['delete_file']) && check_admin_referer('server_cleaner_delete','server_cleaner_delete_nonce')) {
            $file=sanitize_text_field(wp_unslash($_POST['delete_file']));
            if (file_exists($file)) wp_delete_file($file);
        }
    }

    // Login tracking
    public function capture_login($user_login) {
        $ip=$_SERVER['REMOTE_ADDR'];
        $time=current_time('mysql');
        $logins=get_option('server_cleaner_logins',[]);
        array_unshift($logins,['user'=>$user_login,'ip'=>$ip,'time'=>$time]);
        $logins=array_slice($logins,0,50);
        update_option('server_cleaner_logins',$logins);
    }

    private function render_login_activity() {
        $logins=get_option('server_cleaner_logins',[]);
        $your_ip=$_SERVER['REMOTE_ADDR'];

        echo '<h2>Recent Login Activity</h2>';
        echo '<p><strong>Your current IP:</strong> '.esc_html($your_ip).'</p>';
        echo '<table class="widefat striped"><thead><tr><th>User</th><th>IP</th><th>Time</th></tr></thead><tbody>';
        foreach (array_slice($logins,0,10) as $login) {
            $style=$login['ip']===$your_ip?' style="color:green;font-weight:bold;"':'';
            echo "<tr$style><td>".esc_html($login['user'])."</td><td>".esc_html($login['ip'])."</td><td>".esc_html($login['time'])."</td></tr>";
        }
        echo '</tbody></table>';
    }
}
new YPS_Server_Cleaner();
