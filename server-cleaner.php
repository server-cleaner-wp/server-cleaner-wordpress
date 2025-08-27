<?php
/*
Plugin Name: Server Cleaner
Description: Scan your WordPress for duplicate, outdated, or suspicious files. Delete flagged items, monitor logins with geolocation, and keep your site secure.
Version: 1.4.0
Author: Emmanuel Angelo Rigopoulos
License: GPL2
*/

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

require_once plugin_dir_path( __FILE__ ) . 'includes/class-yps-server-cleaner.php';
