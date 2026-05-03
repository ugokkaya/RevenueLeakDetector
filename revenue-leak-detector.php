<?php
/**
 * Plugin Name: Revenue Leak Detector
 * Plugin URI: https://ugur.me
 * Description: Find checkout leaks, cart abandonment points, and the next action to recover WooCommerce conversions.
 * Version: 1.0.0
 * Author: Ugur Can Gokkaya
 * Author URI: https://ugur.me
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: revenue-leak-detector
 * Domain Path: /languages
 */

if (! defined('ABSPATH')) {
    exit;
}

define('REVENUE_LEAK_DETECTOR_CRON_HOOK', 'revenue_leak_detector_send_pending_events');

/**
 * Loads the plugin text domain.
 *
 * @return void
 */
function revenue_leak_detector_load_textdomain()
{
    load_plugin_textdomain(
        'revenue-leak-detector',
        false,
        dirname(plugin_basename(__FILE__)) . '/languages'
    );
}

/**
 * Returns the queue table name.
 *
 * @return string
 */
function revenue_leak_detector_get_queue_table_name()
{
    global $wpdb;

    return $wpdb->prefix . 'rl_events_queue';
}

/**
 * Creates the queue table used for storing event payloads before batch sending.
 *
 * @return void
 */
function revenue_leak_detector_create_queue_table()
{
    global $wpdb;

    $table_name = revenue_leak_detector_get_queue_table_name();
    $charset_collate = $wpdb->get_charset_collate();
    $sql = "CREATE TABLE {$table_name} (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        event_type VARCHAR(191) NOT NULL,
        payload_json LONGTEXT NOT NULL,
        status VARCHAR(50) NOT NULL DEFAULT 'pending',
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY  (id),
        KEY status (status),
        KEY event_type (event_type),
        KEY created_at (created_at)
    ) {$charset_collate};";

    require_once ABSPATH . 'wp-admin/includes/upgrade.php';

    dbDelta($sql);
}

/**
 * Inserts a queue row.
 *
 * @param string       $event_type   Event type identifier.
 * @param string|array $payload      Event payload as JSON string or array.
 * @param string       $status       Queue status.
 *
 * @return int|false
 */
function revenue_leak_detector_insert_queue_event($event_type, $payload, $status = 'pending')
{
    global $wpdb;

    $payload_json = is_string($payload) ? $payload : wp_json_encode($payload);

    if (! is_string($payload_json) || $payload_json === '') {
        return false;
    }

    $result = $wpdb->insert(
        revenue_leak_detector_get_queue_table_name(),
        array(
            'event_type'   => sanitize_text_field($event_type),
            'payload_json' => $payload_json,
            'status'       => sanitize_text_field($status),
            'created_at'   => current_time('mysql', true),
        ),
        array('%s', '%s', '%s', '%s')
    );

    if ($result === false) {
        return false;
    }

    return (int) $wpdb->insert_id;
}

/**
 * Returns a sanitized server value.
 *
 * @param string $key Server array key.
 *
 * @return string
 */
function revenue_leak_detector_get_server_value($key)
{
    if (! isset($_SERVER[$key])) {
        return '';
    }

    $value = wp_unslash($_SERVER[$key]);

    if (is_array($value)) {
        return '';
    }

    return sanitize_text_field((string) $value);
}

/**
 * Returns the best available client IP address for request diagnostics.
 *
 * @return string
 */
function revenue_leak_detector_get_client_ip_address()
{
    $forwarded_for = revenue_leak_detector_get_server_value('HTTP_X_FORWARDED_FOR');

    if ($forwarded_for !== '') {
        $forwarded_parts = array_map('trim', explode(',', $forwarded_for));

        foreach ($forwarded_parts as $ip_address) {
            if (filter_var($ip_address, FILTER_VALIDATE_IP)) {
                return $ip_address;
            }
        }
    }

    $real_ip = revenue_leak_detector_get_server_value('HTTP_X_REAL_IP');

    if ($real_ip !== '' && filter_var($real_ip, FILTER_VALIDATE_IP)) {
        return $real_ip;
    }

    $remote_addr = revenue_leak_detector_get_server_value('REMOTE_ADDR');

    return filter_var($remote_addr, FILTER_VALIDATE_IP) ? $remote_addr : '';
}

/**
 * Returns whether the current user agent is a known crawler or automation client.
 *
 * @param string $user_agent User agent header.
 *
 * @return bool
 */
function revenue_leak_detector_is_known_bot_user_agent($user_agent)
{
    $user_agent = strtolower((string) $user_agent);

    if ($user_agent === '') {
        return false;
    }

    return (bool) preg_match('/bot|crawl|spider|slurp|bingpreview|facebookexternalhit|whatsapp|telegrambot|twitterbot|linkedinbot|pinterest|semrush|ahrefs|mj12bot|dotbot|petalbot|yandex|baiduspider|duckduckbot|headless|phantomjs|python-requests|curl|wget|httpclient|go-http-client/i', $user_agent);
}

/**
 * Returns whether the request is a direct WooCommerce add-to-cart endpoint hit.
 *
 * @return bool
 */
function revenue_leak_detector_is_direct_add_to_cart_request()
{
    $add_to_cart = isset($_REQUEST['add-to-cart']) ? wp_unslash($_REQUEST['add-to-cart']) : '';

    if (! is_array($add_to_cart) && absint($add_to_cart) > 0) {
        return true;
    }

    $wc_ajax = isset($_REQUEST['wc-ajax']) ? wp_unslash($_REQUEST['wc-ajax']) : '';

    if (is_array($wc_ajax)) {
        return false;
    }

    $wc_ajax = sanitize_key($wc_ajax);

    return $wc_ajax === 'add_to_cart';
}

/**
 * Returns request context fields stored with event payloads.
 *
 * @return array<string, mixed>
 */
function revenue_leak_detector_get_request_context()
{
    $user_agent = revenue_leak_detector_get_server_value('HTTP_USER_AGENT');
    $request_uri = revenue_leak_detector_get_server_value('REQUEST_URI');
    $referrer = revenue_leak_detector_get_server_value('HTTP_REFERER');
    $request_method = revenue_leak_detector_get_server_value('REQUEST_METHOD');
    $bot_reasons = array();

    if (revenue_leak_detector_is_known_bot_user_agent($user_agent)) {
        $bot_reasons[] = 'known_bot_user_agent';
    }

    if ($user_agent === '') {
        $bot_reasons[] = 'missing_user_agent';
    }

    return array(
        'ip_address'                    => revenue_leak_detector_get_client_ip_address(),
        'user_agent'                    => $user_agent,
        'referrer'                      => $referrer,
        'request_uri'                   => $request_uri,
        'request_method'                => $request_method,
        'is_ajax'                       => function_exists('wp_doing_ajax') ? wp_doing_ajax() : (defined('DOING_AJAX') && DOING_AJAX),
        'is_direct_add_to_cart_request' => revenue_leak_detector_is_direct_add_to_cart_request(),
        'is_bot'                        => $bot_reasons !== array(),
        'bot_reasons'                   => $bot_reasons,
    );
}

/**
 * Adds request diagnostics to an event payload.
 *
 * @param array<string, mixed> $payload Event payload.
 *
 * @return array<string, mixed>
 */
function revenue_leak_detector_add_request_context_to_payload(array $payload)
{
    return array_merge($payload, revenue_leak_detector_get_request_context());
}

/**
 * Returns a stable visitor key for short-window rate limiting.
 *
 * @return string
 */
function revenue_leak_detector_get_rate_limit_visitor_key()
{
    $session_id = function_exists('WC') && WC()->session ? WC()->session->get_customer_id() : '';

    if (is_string($session_id) && $session_id !== '') {
        return 'session:' . $session_id;
    }

    $ip_address = revenue_leak_detector_get_client_ip_address();
    $user_agent = revenue_leak_detector_get_server_value('HTTP_USER_AGENT');

    return 'ipua:' . md5($ip_address . '|' . $user_agent);
}

/**
 * Increments a short-window rate-limit bucket.
 *
 * @param string $bucket_key Bucket identifier.
 * @param int    $limit      Maximum allowed attempts in the window.
 *
 * @return bool
 */
function revenue_leak_detector_rate_limit_bucket_exceeded($bucket_key, $limit)
{
    $transient_key = 'rld_atc_rl_' . md5($bucket_key);
    $attempts = (int) get_transient($transient_key);

    if ($attempts >= $limit) {
        return true;
    }

    set_transient($transient_key, $attempts + 1, MINUTE_IN_SECONDS);

    return false;
}

/**
 * Returns true when the current request exceeds the add-to-cart rate limit.
 *
 * @param int $product_id Product ID.
 *
 * @return bool
 */
function revenue_leak_detector_is_add_to_cart_rate_limited($product_id)
{
    $product_id = absint($product_id);
    $visitor_key = revenue_leak_detector_get_rate_limit_visitor_key();
    $ip_address = revenue_leak_detector_get_client_ip_address();
    $limits = array(
        array('visitor:' . $visitor_key . '|product:' . $product_id, 5),
        array('ip:' . $ip_address . '|product:' . $product_id, 20),
        array('ip:' . $ip_address . '|all', 60),
    );

    foreach ($limits as $limit) {
        if ($ip_address === '' && strpos($limit[0], 'ip:') === 0) {
            continue;
        }

        if (revenue_leak_detector_rate_limit_bucket_exceeded($limit[0], (int) $limit[1])) {
            return true;
        }
    }

    return false;
}

/**
 * Classifies the current add-to-cart request.
 *
 * @param int $product_id Product ID.
 *
 * @return array{status: string, reasons: array<int, string>}
 */
function revenue_leak_detector_classify_add_to_cart_request($product_id)
{
    $context = revenue_leak_detector_get_request_context();
    $reasons = array();

    if (! empty($context['is_bot'])) {
        $reasons = array_merge($reasons, (array) $context['bot_reasons']);
    }

    if (! empty($context['is_direct_add_to_cart_request']) && empty($context['referrer'])) {
        $reasons[] = 'direct_add_to_cart_without_referrer';
    }

    if (revenue_leak_detector_is_add_to_cart_rate_limited($product_id)) {
        $reasons[] = 'rate_limited';
    }

    return array(
        'status'  => $reasons === array() ? 'pending' : 'ignored',
        'reasons' => array_values(array_unique($reasons)),
    );
}

/**
 * Classifies a page-level funnel request.
 *
 * @return array{status: string, reasons: array<int, string>}
 */
function revenue_leak_detector_classify_funnel_request()
{
    $context = revenue_leak_detector_get_request_context();
    $reasons = array();

    if (! empty($context['is_bot'])) {
        $reasons = array_merge($reasons, (array) $context['bot_reasons']);
    }

    return array(
        'status'  => $reasons === array() ? 'pending' : 'ignored',
        'reasons' => array_values(array_unique($reasons)),
    );
}

/**
 * Classifies order lifecycle events without rejecting server-side gateway hooks.
 *
 * @return array{status: string, reasons: array<int, string>}
 */
function revenue_leak_detector_classify_order_lifecycle_request()
{
    $context = revenue_leak_detector_get_request_context();
    $reasons = array();

    if (! empty($context['bot_reasons']) && in_array('known_bot_user_agent', (array) $context['bot_reasons'], true)) {
        $reasons[] = 'known_bot_user_agent';
    }

    return array(
        'status'  => $reasons === array() ? 'pending' : 'ignored',
        'reasons' => array_values(array_unique($reasons)),
    );
}

/**
 * Adds ignored reasons to a classified payload when needed.
 *
 * @param array<string, mixed>                $payload        Event payload.
 * @param array{status: string, reasons: array<int, string>} $classification Event classification.
 *
 * @return array<string, mixed>
 */
function revenue_leak_detector_apply_event_classification_to_payload(array $payload, array $classification)
{
    if (! empty($classification['reasons'])) {
        $payload['ignored_reasons'] = $classification['reasons'];
    }

    return $payload;
}

/**
 * Inserts an event with request classification applied.
 *
 * @param string               $event_type Event type.
 * @param array<string, mixed> $payload    Event payload.
 * @param array{status: string, reasons: array<int, string>}|null $classification Optional classification.
 *
 * @return int|false
 */
function revenue_leak_detector_insert_classified_queue_event($event_type, array $payload, $classification = null)
{
    if ($classification === null) {
        $classification = revenue_leak_detector_classify_funnel_request();
    }

    return revenue_leak_detector_insert_queue_event(
        $event_type,
        revenue_leak_detector_apply_event_classification_to_payload($payload, $classification),
        isset($classification['status']) ? (string) $classification['status'] : 'pending'
    );
}

/**
 * Returns pending queue events.
 *
 * @param int $limit Maximum number of events.
 *
 * @return array<int, object>
 */
function revenue_leak_detector_get_pending_queue_events($limit = 20)
{
    global $wpdb;

    $limit = max(1, (int) $limit);
    $table_name = revenue_leak_detector_get_queue_table_name();
    $query = $wpdb->prepare(
        "SELECT id, event_type, payload_json, status, created_at
        FROM {$table_name}
        WHERE status = %s
        ORDER BY id ASC
        LIMIT %d",
        'pending',
        $limit
    );

    return (array) $wpdb->get_results($query);
}

/**
 * Returns queue events for a specific status.
 *
 * @param string $status Queue status.
 *
 * @return array<int, object>
 */
function revenue_leak_detector_get_queue_events_by_status($status)
{
    global $wpdb;

    $query = $wpdb->prepare(
        "SELECT id, event_type, payload_json, status, created_at
        FROM " . revenue_leak_detector_get_queue_table_name() . "
        WHERE status = %s
        ORDER BY id ASC",
        sanitize_text_field($status)
    );

    return (array) $wpdb->get_results($query);
}

/**
 * Returns sanitized local dashboard date filters.
 *
 * @return array{start_date: string, end_date: string, preset: string}
 */
function revenue_leak_detector_get_local_dashboard_filters()
{
    $preset = isset($_GET['preset']) ? sanitize_key(wp_unslash($_GET['preset'])) : '30d';
    $start_date = isset($_GET['start_date']) ? sanitize_text_field(wp_unslash($_GET['start_date'])) : '';
    $end_date = isset($_GET['end_date']) ? sanitize_text_field(wp_unslash($_GET['end_date'])) : '';
    $preset_map = array(
        'today' => 1,
        'yesterday' => 1,
        '7d'    => 7,
        '14d'   => 14,
        '30d'   => 30,
    );

    if (isset($preset_map[$preset])) {
        $days = (int) $preset_map[$preset];
        $base_timestamp = $preset === 'yesterday'
            ? strtotime('-1 day')
            : time();
        $end_date = gmdate('Y-m-d', $base_timestamp);
        $start_date = gmdate('Y-m-d', strtotime('-' . ($days - 1) . ' days', $base_timestamp));
    }

    if (! preg_match('/^\d{4}-\d{2}-\d{2}$/', $start_date)) {
        $start_date = gmdate('Y-m-d', strtotime('-29 days'));
    }

    if (! preg_match('/^\d{4}-\d{2}-\d{2}$/', $end_date)) {
        $end_date = gmdate('Y-m-d');
    }

    if ($start_date > $end_date) {
        $tmp = $start_date;
        $start_date = $end_date;
        $end_date = $tmp;
    }

    return array(
        'start_date' => $start_date,
        'end_date'   => $end_date,
        'preset'     => isset($preset_map[$preset]) ? $preset : 'custom',
    );
}

/**
 * Builds SQL range arguments for the queue created_at column.
 *
 * @param array{start_date: string, end_date: string} $filters Date filters.
 *
 * @return array{sql: string, params: array<int, string>}
 */
function revenue_leak_detector_get_queue_date_range_clause(array $filters)
{
    return array(
        'sql'    => ' created_at >= %s AND created_at <= %s ',
        'params' => array(
            $filters['start_date'] . ' 00:00:00',
            $filters['end_date'] . ' 23:59:59',
        ),
    );
}

/**
 * Returns aggregate counts grouped by event type.
 *
 * @return array<string, int>
 */
function revenue_leak_detector_get_event_counts_by_type(array $filters)
{
    global $wpdb;

    $range = revenue_leak_detector_get_queue_date_range_clause($filters);
    $query = $wpdb->prepare(
        "SELECT event_type, COUNT(*) AS total
        FROM " . revenue_leak_detector_get_queue_table_name() . "
        WHERE {$range['sql']}
        AND status <> %s
        GROUP BY event_type
        ORDER BY total DESC, event_type ASC",
        array_merge($range['params'], array('ignored'))
    );
    $results = (array) $wpdb->get_results($query);
    $counts = array();

    foreach ($results as $row) {
        $counts[(string) $row->event_type] = (int) $row->total;
    }

    return $counts;
}

/**
 * Returns queue events for the given filters and event types.
 *
 * @param array<string, string> $filters     Date filters.
 * @param array<int, string>    $event_types Event keys.
 *
 * @return array<int, object>
 */
function revenue_leak_detector_get_queue_events_for_filters(array $filters, array $event_types)
{
    global $wpdb;

    $event_types = array_values(array_filter(array_map('sanitize_text_field', $event_types)));

    if ($event_types === array()) {
        return array();
    }

    $range = revenue_leak_detector_get_queue_date_range_clause($filters);
    $placeholders = implode(', ', array_fill(0, count($event_types), '%s'));
    $query = $wpdb->prepare(
        "SELECT id, event_type, payload_json, status, created_at
        FROM " . revenue_leak_detector_get_queue_table_name() . "
        WHERE {$range['sql']}
        AND status <> %s
        AND event_type IN ({$placeholders})
        ORDER BY id DESC",
        array_merge($range['params'], array('ignored'), $event_types)
    );

    return (array) $wpdb->get_results($query);
}

/**
 * Returns daily event totals for the last N days ending on the filtered end date.
 *
 * @param array{start_date: string, end_date: string} $filters Date filters.
 * @param int                                         $days    Number of days.
 *
 * @return array<int, array<string, int|string>>
 */
function revenue_leak_detector_get_daily_trend_data(array $filters, $days = 7)
{
    global $wpdb;

    $days = max(1, (int) $days);
    $end_timestamp = strtotime($filters['end_date'] . ' 00:00:00 UTC');

    if ($end_timestamp === false) {
        $end_timestamp = time();
    }

    $start_timestamp = strtotime('-' . ($days - 1) . ' days', $end_timestamp);
    $start_date = gmdate('Y-m-d', $start_timestamp);
    $end_date = gmdate('Y-m-d', $end_timestamp);
    $query = $wpdb->prepare(
        "SELECT DATE(created_at) AS day_key, event_type, COUNT(*) AS total
        FROM " . revenue_leak_detector_get_queue_table_name() . "
        WHERE created_at >= %s
        AND created_at <= %s
        AND status <> %s
        AND event_type IN (%s, %s)
        GROUP BY DATE(created_at), event_type
        ORDER BY day_key ASC",
        $start_date . ' 00:00:00',
        $end_date . ' 23:59:59',
        'ignored',
        'add_to_cart',
        'payment_success'
    );
    $results = (array) $wpdb->get_results($query);
    $indexed = array();

    foreach ($results as $row) {
        $day_key = (string) $row->day_key;

        if (! isset($indexed[$day_key])) {
            $indexed[$day_key] = array(
                'add_to_cart'     => 0,
                'payment_success' => 0,
            );
        }

        $indexed[$day_key][(string) $row->event_type] = (int) $row->total;
    }

    $trend = array();

    for ($offset = 0; $offset < $days; $offset++) {
        $day_timestamp = strtotime('+' . $offset . ' days', $start_timestamp);
        $day_key = gmdate('Y-m-d', $day_timestamp);
        $trend[] = array(
            'date'            => $day_key,
            'label'           => gmdate('M j', $day_timestamp),
            'add_to_cart'     => isset($indexed[$day_key]['add_to_cart']) ? (int) $indexed[$day_key]['add_to_cart'] : 0,
            'payment_success' => isset($indexed[$day_key]['payment_success']) ? (int) $indexed[$day_key]['payment_success'] : 0,
        );
    }

    return $trend;
}

/**
 * Returns normalized product metadata.
 *
 * @param int $product_id Product or variation ID.
 *
 * @return array<string, mixed>
 */
function revenue_leak_detector_get_product_context($product_id)
{
    $product_id = absint($product_id);
    $context = array(
        'product_id'      => $product_id,
        'variation_id'    => 0,
        'product_name'    => '',
        'product_sku'     => '',
        'price'           => 0.0,
        'category_ids'    => array(),
        'category_names'  => array(),
    );

    if (! function_exists('wc_get_product') || $product_id <= 0) {
        return $context;
    }

    $product = wc_get_product($product_id);

    if (! $product) {
        return $context;
    }

    $resolved_product_id = (int) $product->get_id();
    $parent_product_id = method_exists($product, 'get_parent_id') ? (int) $product->get_parent_id() : 0;
    $taxonomy_product_id = $parent_product_id > 0 ? $parent_product_id : $resolved_product_id;
    $category_terms = function_exists('get_the_terms') ? get_the_terms($taxonomy_product_id, 'product_cat') : false;
    $category_ids = array();
    $category_names = array();

    if (is_array($category_terms)) {
        foreach ($category_terms as $term) {
            if (! is_object($term) || ! isset($term->term_id, $term->name)) {
                continue;
            }

            $category_ids[] = (int) $term->term_id;
            $category_names[] = sanitize_text_field((string) $term->name);
        }
    }

    $context['product_id'] = $parent_product_id > 0 ? $parent_product_id : $resolved_product_id;
    $context['variation_id'] = $parent_product_id > 0 ? $resolved_product_id : 0;
    $context['product_name'] = $product->get_name();
    $context['product_sku'] = $product->get_sku();
    $context['price'] = (float) $product->get_price();
    $context['category_ids'] = array_values(array_unique(array_filter(array_map('absint', $category_ids))));
    $context['category_names'] = array_values(array_unique(array_filter(array_map('sanitize_text_field', $category_names))));

    return $context;
}

/**
 * Builds a normalized line item payload.
 *
 * @param int        $product_id   Product ID.
 * @param int        $quantity     Quantity.
 * @param float      $unit_price   Unit price.
 * @param float|null $line_total   Line total.
 * @param int        $variation_id Variation ID.
 *
 * @return array<string, mixed>
 */
function revenue_leak_detector_build_item_payload($product_id, $quantity, $unit_price = 0.0, $line_total = null, $variation_id = 0)
{
    $product_context = revenue_leak_detector_get_product_context($variation_id > 0 ? $variation_id : $product_id);
    $quantity = max(1, absint($quantity));
    $resolved_unit_price = (float) $unit_price;

    if ($resolved_unit_price <= 0 && isset($product_context['price'])) {
        $resolved_unit_price = (float) $product_context['price'];
    }

    if ($line_total === null || (float) $line_total <= 0) {
        $line_total = $resolved_unit_price * $quantity;
    }

    return array(
        'product_id'      => (int) $product_context['product_id'],
        'variation_id'    => $variation_id > 0 ? absint($variation_id) : (int) $product_context['variation_id'],
        'product_name'    => (string) $product_context['product_name'],
        'product_sku'     => (string) $product_context['product_sku'],
        'quantity'        => $quantity,
        'unit_price'      => $resolved_unit_price,
        'line_total'      => (float) $line_total,
        'category_ids'    => isset($product_context['category_ids']) ? $product_context['category_ids'] : array(),
        'category_names'  => isset($product_context['category_names']) ? $product_context['category_names'] : array(),
    );
}

/**
 * Builds item payloads from the current WooCommerce cart.
 *
 * @return array<int, array<string, mixed>>
 */
function revenue_leak_detector_build_cart_items_payload()
{
    if (! function_exists('WC') || ! WC()->cart) {
        return array();
    }

    $items = array();

    foreach ((array) WC()->cart->get_cart() as $cart_item) {
        $product_id = isset($cart_item['product_id']) ? absint($cart_item['product_id']) : 0;
        $variation_id = isset($cart_item['variation_id']) ? absint($cart_item['variation_id']) : 0;
        $quantity = isset($cart_item['quantity']) ? absint($cart_item['quantity']) : 1;
        $line_total = isset($cart_item['line_total']) ? (float) $cart_item['line_total'] : null;
        $product = isset($cart_item['data']) && is_object($cart_item['data']) ? $cart_item['data'] : null;
        $unit_price = $product && method_exists($product, 'get_price') ? (float) $product->get_price() : 0.0;

        $items[] = revenue_leak_detector_build_item_payload($product_id, $quantity, $unit_price, $line_total, $variation_id);
    }

    return $items;
}

/**
 * Builds item payloads from a WooCommerce order.
 *
 * @param WC_Order $order WooCommerce order.
 *
 * @return array<int, array<string, mixed>>
 */
function revenue_leak_detector_build_order_items_payload($order)
{
    if (! $order || ! is_a($order, 'WC_Order')) {
        return array();
    }

    $items = array();

    foreach ($order->get_items() as $item) {
        if (! is_a($item, 'WC_Order_Item_Product')) {
            continue;
        }

        $quantity = (int) $item->get_quantity();

        if ($quantity <= 0) {
            continue;
        }

        $product_id = (int) $item->get_product_id();
        $variation_id = (int) $item->get_variation_id();
        $line_total = (float) $item->get_total();
        $unit_price = $quantity > 0 ? ($line_total / $quantity) : 0.0;

        $items[] = revenue_leak_detector_build_item_payload($product_id, $quantity, $unit_price, $line_total, $variation_id);
    }

    return $items;
}

/**
 * Extracts normalized items from an event payload.
 *
 * @param array<string, mixed> $payload    Event payload.
 * @param string               $event_type Event key.
 *
 * @return array<int, array<string, mixed>>
 */
function revenue_leak_detector_extract_items_from_payload(array $payload, $event_type = '')
{
    if (isset($payload['items']) && is_array($payload['items'])) {
        return array_values(array_filter($payload['items'], 'is_array'));
    }

    if (isset($payload['product_id']) && (int) $payload['product_id'] > 0) {
        return array(
            array(
                'product_id'      => absint($payload['product_id']),
                'variation_id'    => isset($payload['variation_id']) ? absint($payload['variation_id']) : 0,
                'product_name'    => isset($payload['product_name']) ? sanitize_text_field((string) $payload['product_name']) : '',
                'product_sku'     => isset($payload['product_sku']) ? sanitize_text_field((string) $payload['product_sku']) : '',
                'quantity'        => isset($payload['quantity']) ? max(1, absint($payload['quantity'])) : 1,
                'unit_price'      => isset($payload['price']) ? (float) $payload['price'] : 0.0,
                'line_total'      => isset($payload['line_total']) ? (float) $payload['line_total'] : ((isset($payload['price'], $payload['quantity']) ? (float) $payload['price'] * max(1, absint($payload['quantity'])) : 0.0)),
                'category_ids'    => isset($payload['category_ids']) && is_array($payload['category_ids']) ? array_values(array_map('absint', $payload['category_ids'])) : array(),
                'category_names'  => isset($payload['category_names']) && is_array($payload['category_names']) ? array_values(array_map('sanitize_text_field', $payload['category_names'])) : array(),
            ),
        );
    }

    return array();
}

/**
 * Returns whether developer-facing settings should be visible.
 *
 * @return bool
 */
function revenue_leak_detector_should_show_developer_settings()
{
    return defined('WP_DEBUG') && WP_DEBUG;
}

/**
 * Builds a prioritized list of insight issues from local funnel metrics.
 *
 * @param array<string, mixed> $summary Summary metrics.
 *
 * @return array<int, array<string, mixed>>
 */
function revenue_leak_detector_build_local_issues(array $summary)
{
    $issues = array();
    $checkout_dropoff_users = max(0, (int) $summary['begin_checkout'] - (int) $summary['payment_success']);
    $cart_dropoff_users = max(0, (int) $summary['add_to_cart'] - (int) $summary['begin_checkout']);

    if ($summary['begin_checkout'] >= 5 && $summary['checkout_abandon_rate'] >= 0.7) {
        $issues[] = array(
            'severity'    => 'high',
            'severity_no' => 3,
            'title'       => __('High Checkout Abandonment', 'revenue-leak-detector'),
            'explanation' => sprintf(
                /* translators: %s is a percentage. */
                __('%s of users who started checkout did not complete purchase.', 'revenue-leak-detector'),
                $summary['checkout_abandon_rate_label']
            ),
            'impact'      => sprintf(
                /* translators: %d is a user count. */
                __('You likely lost %d ready-to-buy users after checkout started.', 'revenue-leak-detector'),
                $checkout_dropoff_users
            ),
            'lost_users'  => $checkout_dropoff_users,
            'action'      => __('Review checkout flow, remove payment friction, and shorten the form.', 'revenue-leak-detector'),
        );
    }

    if ($summary['add_to_cart'] >= 5 && $summary['checkout_start_rate'] < 0.6) {
        $issues[] = array(
            'severity'    => $summary['checkout_start_rate'] < 0.4 ? 'high' : 'medium',
            'severity_no' => $summary['checkout_start_rate'] < 0.4 ? 3 : 2,
            'title'       => __('Weak Cart to Checkout Progression', 'revenue-leak-detector'),
            'explanation' => sprintf(
                /* translators: %s is a percentage. */
                __('Only %s of add-to-cart sessions moved into checkout.', 'revenue-leak-detector'),
                $summary['checkout_start_rate_label']
            ),
            'impact'      => sprintf(
                /* translators: %d is a user count. */
                __('%d shoppers added products but never reached checkout.', 'revenue-leak-detector'),
                $cart_dropoff_users
            ),
            'lost_users'  => $cart_dropoff_users,
            'action'      => __('Strengthen the cart CTA and remove distractions before checkout.', 'revenue-leak-detector'),
        );
    }

    if ($summary['order_failed'] >= max(3, (int) ceil($summary['payment_success'] * 0.15))) {
        $issues[] = array(
            'severity'    => 'medium',
            'severity_no' => 2,
            'title'       => __('Order Failures Need Attention', 'revenue-leak-detector'),
            'explanation' => sprintf(
                /* translators: %d is an event count. */
                __('%d orders failed during the selected period.', 'revenue-leak-detector'),
                $summary['order_failed']
            ),
            'impact'      => __('Customers reached payment but revenue was not captured.', 'revenue-leak-detector'),
            'lost_users'  => (int) $summary['order_failed'],
            'action'      => __('Audit gateway errors now and resolve the top failure reasons.', 'revenue-leak-detector'),
        );
    }

    if ($summary['refund_rate'] >= 0.08 && $summary['payment_success'] >= 5) {
        $issues[] = array(
            'severity'    => 'medium',
            'severity_no' => 2,
            'title'       => __('Refund Rate Is Elevated', 'revenue-leak-detector'),
            'explanation' => sprintf(
                /* translators: %s is a percentage. */
                __('Refunds equal %s of successful purchases.', 'revenue-leak-detector'),
                $summary['refund_rate_label']
            ),
            'impact'      => __('Revenue is being recovered after purchase, which weakens net conversion.', 'revenue-leak-detector'),
            'lost_users'  => (int) $summary['refund'],
            'action'      => __('Review refund reasons and align the product promise with checkout expectations.', 'revenue-leak-detector'),
        );
    }

    if ($issues === array()) {
        $issues[] = array(
            'severity'    => 'low',
            'severity_no' => 0,
            'title'       => __('No Critical Funnel Leak Detected', 'revenue-leak-detector'),
            'explanation' => __('Current funnel metrics look stable for the selected date range.', 'revenue-leak-detector'),
            'impact'      => __('No major revenue leak signal stands out right now.', 'revenue-leak-detector'),
            'lost_users'  => 0,
            'action'      => __('Keep monitoring trends and focus on improving conversion step by step.', 'revenue-leak-detector'),
        );
    }

    usort(
        $issues,
        static function ($left, $right) {
            return (int) $right['severity_no'] <=> (int) $left['severity_no'];
        }
    );

    return $issues;
}

/**
 * Returns local queue dashboard metrics.
 *
 * @return array<string, mixed>
 */
function revenue_leak_detector_get_local_dashboard_data(array $filters)
{
    $event_counts = revenue_leak_detector_get_event_counts_by_type($filters);
    $funnel_keys = array(
        'view_cart',
        'add_to_cart',
        'remove_from_cart',
        'begin_checkout',
        'add_shipping_info',
        'add_payment_info',
        'payment_success',
        'order_failed',
        'order_cancelled',
        'refund',
    );
    $funnel = array();

    foreach ($funnel_keys as $event_key) {
        $funnel[$event_key] = isset($event_counts[$event_key]) ? (int) $event_counts[$event_key] : 0;
    }

    $add_to_cart = $funnel['add_to_cart'];
    $begin_checkout = $funnel['begin_checkout'];
    $payment_success = $funnel['payment_success'];
    $cart_dropoff_users = max(0, $add_to_cart - $begin_checkout);
    $checkout_dropoff_users = max(0, $begin_checkout - $payment_success);
    $checkout_abandon_rate = $begin_checkout > 0 ? max(0, 1 - ($payment_success / $begin_checkout)) : 0;
    $conversion_rate = $add_to_cart > 0 ? ($payment_success / $add_to_cart) : 0;
    $checkout_start_rate = $add_to_cart > 0 ? ($begin_checkout / $add_to_cart) : 0;
    $refund_rate = $payment_success > 0 ? ($funnel['refund'] / $payment_success) : 0;
    $score_penalty = ($checkout_abandon_rate * 55) + ((1 - $conversion_rate) * 25) + (($funnel['order_failed'] > 0 ? min(1, $funnel['order_failed'] / max(1, $payment_success)) : 0) * 12) + ($refund_rate * 8);
    $leak_score = (int) max(0, min(100, round(100 - $score_penalty)));
    $primary_leak_label = $cart_dropoff_users >= $checkout_dropoff_users
        ? __('Cart to Checkout', 'revenue-leak-detector')
        : __('Checkout to Purchase', 'revenue-leak-detector');
    $primary_leak_count = max($cart_dropoff_users, $checkout_dropoff_users);
    $primary_leak_rate = $cart_dropoff_users >= $checkout_dropoff_users
        ? (1 - $checkout_start_rate)
        : $checkout_abandon_rate;
    $summary = array(
        'add_to_cart'                  => $add_to_cart,
        'begin_checkout'               => $begin_checkout,
        'payment_success'              => $payment_success,
        'order_failed'                 => $funnel['order_failed'],
        'checkout_dropoff_users'       => $checkout_dropoff_users,
        'cart_dropoff_users'           => $cart_dropoff_users,
        'refund'                       => $funnel['refund'],
        'checkout_abandon_rate'        => $checkout_abandon_rate,
        'checkout_abandon_rate_label'  => round($checkout_abandon_rate * 100, 1) . '%',
        'conversion_rate'              => $conversion_rate,
        'conversion_rate_label'        => round($conversion_rate * 100, 1) . '%',
        'checkout_start_rate'          => $checkout_start_rate,
        'checkout_start_rate_label'    => round($checkout_start_rate * 100, 1) . '%',
        'refund_rate'                  => $refund_rate,
        'refund_rate_label'            => round($refund_rate * 100, 1) . '%',
        'primary_leak_label'           => $primary_leak_label,
        'primary_leak_count'           => $primary_leak_count,
        'primary_leak_rate'            => $primary_leak_rate,
        'primary_leak_rate_label'      => round($primary_leak_rate * 100, 1) . '%',
        'leak_score'                   => $leak_score,
    );
    $issues = revenue_leak_detector_build_local_issues($summary);

    return array(
        'total_events'     => array_sum($event_counts),
        'failed_checkout'  => $funnel['begin_checkout'] - $funnel['payment_success'],
        'filters'          => $filters,
        'summary'          => $summary,
        'top_issue'        => $issues[0],
        'issues'           => $issues,
        'trend'            => revenue_leak_detector_get_daily_trend_data($filters, 7),
        'event_counts'     => $event_counts,
        'funnel'           => $funnel,
    );
}

/**
 * Reserves pending queue events for a single batch run.
 *
 * @param int $limit Maximum number of events.
 *
 * @return array{status: string, events: array<int, object>}
 */
function revenue_leak_detector_reserve_pending_queue_events($limit = 20)
{
    global $wpdb;

    $events = revenue_leak_detector_get_pending_queue_events($limit);

    if ($events === array()) {
        return array(
            'status' => '',
            'events' => array(),
        );
    }

    $event_ids = array_map(
        static function ($event) {
            return (int) $event->id;
        },
        $events
    );
    $reservation_status = 'processing_' . wp_generate_password(12, false, false);
    $placeholders = implode(', ', array_fill(0, count($event_ids), '%d'));
    $update_query = $wpdb->prepare(
        "UPDATE " . revenue_leak_detector_get_queue_table_name() . "
        SET status = %s
        WHERE status = %s
        AND id IN ({$placeholders})",
        array_merge(array($reservation_status, 'pending'), $event_ids)
    );

    $wpdb->query($update_query);

    return array(
        'status' => $reservation_status,
        'events' => revenue_leak_detector_get_queue_events_by_status($reservation_status),
    );
}

/**
 * Updates queue events from one status to another.
 *
 * @param array<int, int> $event_ids Queue event IDs.
 * @param string          $from_status Current status.
 * @param string          $to_status Target status.
 *
 * @return int|false
 */
function revenue_leak_detector_update_queue_event_status(array $event_ids, $from_status, $to_status)
{
    global $wpdb;

    $event_ids = array_values(array_filter(array_map('absint', $event_ids)));

    if ($event_ids === array()) {
        return 0;
    }

    $placeholders = implode(', ', array_fill(0, count($event_ids), '%d'));
    $query = $wpdb->prepare(
        "UPDATE " . revenue_leak_detector_get_queue_table_name() . "
        SET status = %s
        WHERE status = %s
        AND id IN ({$placeholders})",
        array_merge(array(sanitize_text_field($to_status), sanitize_text_field($from_status)), $event_ids)
    );

    return $wpdb->query($query);
}

/**
 * Marks queue events as sent.
 *
 * @param array<int, int> $event_ids Queue event IDs.
 * @param string          $from_status Current status.
 *
 * @return int|false
 */
function revenue_leak_detector_mark_queue_events_sent(array $event_ids, $from_status = 'pending')
{
    return revenue_leak_detector_update_queue_event_status($event_ids, $from_status, 'sent');
}

/**
 * Returns reserved queue events back to pending.
 *
 * @param array<int, int> $event_ids Queue event IDs.
 * @param string          $from_status Current status.
 *
 * @return int|false
 */
function revenue_leak_detector_release_queue_events(array $event_ids, $from_status)
{
    return revenue_leak_detector_update_queue_event_status($event_ids, $from_status, 'pending');
}

/**
 * Returns the current cart fingerprint.
 *
 * @return string
 */
function revenue_leak_detector_get_cart_fingerprint()
{
    if (! function_exists('WC') || ! WC()->cart) {
        return 'no-cart';
    }

    $cart_hash = WC()->cart->get_cart_hash();

    if (is_string($cart_hash) && $cart_hash !== '') {
        return $cart_hash;
    }

    $encoded_cart = wp_json_encode(WC()->cart->get_cart());

    if (is_string($encoded_cart) && $encoded_cart !== '') {
        return md5($encoded_cart);
    }

    return 'cart-present';
}

/**
 * Returns true when the current request targets the checkout page.
 *
 * @return bool
 */
function revenue_leak_detector_is_checkout_request()
{
    if (function_exists('is_checkout') && is_checkout()) {
        return true;
    }

    if (isset($_GET['page_id']) && absint($_GET['page_id']) === absint(wc_get_page_id('checkout'))) {
        return true;
    }

    return false;
}

/**
 * Returns true when the current request targets an order-pay route.
 *
 * @return bool
 */
function revenue_leak_detector_is_checkout_pay_request()
{
    if (function_exists('is_checkout_pay_page') && is_checkout_pay_page()) {
        return true;
    }

    $request_uri = isset($_SERVER['REQUEST_URI']) ? wp_unslash($_SERVER['REQUEST_URI']) : '';

    return is_string($request_uri) && strpos($request_uri, 'order-pay') !== false;
}

/**
 * Returns true when the current request targets an order-received route.
 *
 * @return bool
 */
function revenue_leak_detector_is_order_received_request()
{
    if (function_exists('is_order_received_page') && is_order_received_page()) {
        return true;
    }

    if (isset($_GET['order-received']) && absint($_GET['order-received']) > 0) {
        return true;
    }

    $request_uri = isset($_SERVER['REQUEST_URI']) ? wp_unslash($_SERVER['REQUEST_URI']) : '';

    return is_string($request_uri) && strpos($request_uri, 'order-received') !== false;
}

/**
 * Checks whether the current cart has already produced a begin_checkout event.
 *
 * @return bool
 */
function revenue_leak_detector_should_capture_begin_checkout()
{
    if (! function_exists('WC') || ! WC()->session) {
        return false;
    }

    if (WC()->cart && WC()->cart->is_empty()) {
        if (! revenue_leak_detector_is_checkout_pay_request()) {
            return false;
        }
    }

    $current_fingerprint = revenue_leak_detector_get_cart_fingerprint();
    $last_fingerprint = WC()->session->get('revenue_leak_detector_begin_checkout_hash', '');

    return is_string($current_fingerprint) && $current_fingerprint !== '' && $current_fingerprint !== $last_fingerprint;
}

/**
 * Remembers the cart fingerprint for begin_checkout deduplication.
 *
 * @return void
 */
function revenue_leak_detector_mark_begin_checkout_captured()
{
    if (! function_exists('WC') || ! WC()->session) {
        return;
    }

    WC()->session->set(
        'revenue_leak_detector_begin_checkout_hash',
        revenue_leak_detector_get_cart_fingerprint()
    );
}

/**
 * Checks whether the current cart has already produced a view_cart event.
 *
 * @return bool
 */
function revenue_leak_detector_should_capture_view_cart()
{
    if (! function_exists('WC') || ! WC()->session || ! WC()->cart || WC()->cart->is_empty()) {
        return false;
    }

    $current_fingerprint = revenue_leak_detector_get_cart_fingerprint();
    $last_fingerprint = WC()->session->get('revenue_leak_detector_view_cart_hash', '');

    return is_string($current_fingerprint) && $current_fingerprint !== '' && $current_fingerprint !== $last_fingerprint;
}

/**
 * Remembers the cart fingerprint for view_cart deduplication.
 *
 * @return void
 */
function revenue_leak_detector_mark_view_cart_captured()
{
    if (! function_exists('WC') || ! WC()->session) {
        return;
    }

    WC()->session->set(
        'revenue_leak_detector_view_cart_hash',
        revenue_leak_detector_get_cart_fingerprint()
    );
}

/**
 * Clears the begin_checkout dedupe marker when the cart changes.
 *
 * @return void
 */
function revenue_leak_detector_reset_begin_checkout_marker()
{
    if (! function_exists('WC') || ! WC()->session) {
        return;
    }

    WC()->session->set('revenue_leak_detector_begin_checkout_hash', '');
    WC()->session->set('revenue_leak_detector_view_cart_hash', '');
}

/**
 * Validates a nonce for admin-post actions.
 *
 * @param string $action Nonce action.
 *
 * @return void
 */
function revenue_leak_detector_verify_admin_nonce($action)
{
    $nonce = isset($_REQUEST['_wpnonce']) ? sanitize_text_field(wp_unslash($_REQUEST['_wpnonce'])) : '';

    if (! wp_verify_nonce($nonce, $action)) {
        wp_die(esc_html__('Security check failed.', 'revenue-leak-detector'));
    }
}

/**
 * Renders admin notices for plugin actions.
 *
 * @return void
 */
function revenue_leak_detector_render_action_notices()
{
    if (isset($_GET['settings-updated'])) {
        echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('Settings saved.', 'revenue-leak-detector') . '</p></div>';
    }
}

/**
 * Builds the payload for an add_to_cart event.
 *
 * @param int $product_id Product ID.
 * @param int $quantity   Added quantity.
 *
 * @return array<string, mixed>
 */
function revenue_leak_detector_build_add_to_cart_payload($product_id, $quantity)
{
    $product_id = absint($product_id);
    $quantity = max(1, absint($quantity));
    $item_payload = revenue_leak_detector_build_item_payload($product_id, $quantity);
    $payload = array(
        'product_id'   => $product_id,
        'quantity'     => $quantity,
        'user_id'      => get_current_user_id(),
        'session_id'   => function_exists('WC') && WC()->session ? WC()->session->get_customer_id() : '',
        'occurred_at'  => current_time('mysql', true),
        'category_ids' => isset($item_payload['category_ids']) ? $item_payload['category_ids'] : array(),
        'category_names' => isset($item_payload['category_names']) ? $item_payload['category_names'] : array(),
        'line_total'   => isset($item_payload['line_total']) ? (float) $item_payload['line_total'] : 0.0,
        'items'        => array($item_payload),
    );

    if (function_exists('wc_get_product')) {
        $product = wc_get_product($product_id);

        if ($product) {
            $payload['product_name'] = $product->get_name();
            $payload['product_sku'] = $product->get_sku();
            $payload['price'] = (float) $product->get_price();
            $payload['variation_id'] = $product->is_type('variation') ? (int) $product->get_id() : 0;
        }
    }

    return revenue_leak_detector_add_request_context_to_payload($payload);
}

/**
 * Builds the payload for a begin_checkout event.
 *
 * @return array<string, mixed>
 */
function revenue_leak_detector_build_begin_checkout_payload()
{
    $payload = array(
        'user_id'     => get_current_user_id(),
        'session_id'  => function_exists('WC') && WC()->session ? WC()->session->get_customer_id() : '',
        'occurred_at' => current_time('mysql', true),
        'cart_total'  => function_exists('WC') && WC()->cart ? (float) WC()->cart->get_total('edit') : 0,
        'item_count'  => function_exists('WC') && WC()->cart ? (int) WC()->cart->get_cart_contents_count() : 0,
        'currency'    => function_exists('get_woocommerce_currency') ? get_woocommerce_currency() : get_option('woocommerce_currency', ''),
        'cart_hash'   => revenue_leak_detector_get_cart_fingerprint(),
        'items'       => revenue_leak_detector_build_cart_items_payload(),
    );

    return revenue_leak_detector_add_request_context_to_payload($payload);
}

/**
 * Builds a cart-level payload used by cart and checkout funnel events.
 *
 * @return array<string, mixed>
 */
function revenue_leak_detector_build_cart_context_payload()
{
    return revenue_leak_detector_add_request_context_to_payload(array(
        'user_id'        => get_current_user_id(),
        'session_id'     => function_exists('WC') && WC()->session ? WC()->session->get_customer_id() : '',
        'occurred_at'    => current_time('mysql', true),
        'cart_total'     => function_exists('WC') && WC()->cart ? (float) WC()->cart->get_total('edit') : 0,
        'item_count'     => function_exists('WC') && WC()->cart ? (int) WC()->cart->get_cart_contents_count() : 0,
        'cart_hash'      => revenue_leak_detector_get_cart_fingerprint(),
        'currency'       => function_exists('get_woocommerce_currency') ? get_woocommerce_currency() : get_option('woocommerce_currency', ''),
    ));
}

/**
 * Builds the payload for a view_cart event.
 *
 * @return array<string, mixed>
 */
function revenue_leak_detector_build_view_cart_payload()
{
    return revenue_leak_detector_build_cart_context_payload();
}

/**
 * Builds the payload for a remove_from_cart event.
 *
 * @param int $product_id Product ID.
 * @param int $quantity Removed quantity.
 *
 * @return array<string, mixed>
 */
function revenue_leak_detector_build_remove_from_cart_payload($product_id, $quantity)
{
    $item_payload = revenue_leak_detector_build_item_payload($product_id, $quantity);

    return array_merge(
        revenue_leak_detector_build_cart_context_payload(),
        array(
            'product_id'      => absint($product_id),
            'quantity'        => max(1, absint($quantity)),
            'variation_id'    => isset($item_payload['variation_id']) ? (int) $item_payload['variation_id'] : 0,
            'product_name'    => isset($item_payload['product_name']) ? (string) $item_payload['product_name'] : '',
            'product_sku'     => isset($item_payload['product_sku']) ? (string) $item_payload['product_sku'] : '',
            'category_ids'    => isset($item_payload['category_ids']) ? $item_payload['category_ids'] : array(),
            'category_names'  => isset($item_payload['category_names']) ? $item_payload['category_names'] : array(),
            'line_total'      => isset($item_payload['line_total']) ? (float) $item_payload['line_total'] : 0.0,
            'items'           => array($item_payload),
        )
    );
}

/**
 * Builds the payload for an add_shipping_info event.
 *
 * @param WC_Order $order WooCommerce order.
 *
 * @return array<string, mixed>
 */
function revenue_leak_detector_build_add_shipping_info_payload($order)
{
    return revenue_leak_detector_add_request_context_to_payload(array(
        'order_id'         => (int) $order->get_id(),
        'user_id'          => (int) $order->get_user_id(),
        'occurred_at'      => current_time('mysql', true),
        'shipping_total'   => (float) $order->get_shipping_total(),
        'shipping_method'  => $order->get_shipping_method(),
        'requires_shipping'=> $order->needs_shipping_address(),
        'currency'         => $order->get_currency(),
        'total'            => (float) $order->get_total(),
        'item_count'       => (int) $order->get_item_count(),
        'items'            => revenue_leak_detector_build_order_items_payload($order),
    ));
}

/**
 * Builds the payload for an add_payment_info event.
 *
 * @param WC_Order $order WooCommerce order.
 *
 * @return array<string, mixed>
 */
function revenue_leak_detector_build_add_payment_info_payload($order)
{
    return revenue_leak_detector_add_request_context_to_payload(array(
        'order_id'        => (int) $order->get_id(),
        'user_id'         => (int) $order->get_user_id(),
        'occurred_at'     => current_time('mysql', true),
        'payment_method'  => $order->get_payment_method(),
        'payment_method_title' => $order->get_payment_method_title(),
        'currency'        => $order->get_currency(),
        'total'           => (float) $order->get_total(),
        'item_count'      => (int) $order->get_item_count(),
        'items'           => revenue_leak_detector_build_order_items_payload($order),
    ));
}

/**
 * Builds the payload for an order lifecycle event.
 *
 * @param int    $order_id WooCommerce order ID.
 * @param string $event_type Event type.
 *
 * @return array<string, mixed>
 */
function revenue_leak_detector_build_order_lifecycle_payload($order_id, $event_type)
{
    $payload = array(
        'order_id'    => absint($order_id),
        'event_type'  => sanitize_text_field($event_type),
        'occurred_at' => current_time('mysql', true),
    );

    if (! function_exists('wc_get_order')) {
        return revenue_leak_detector_add_request_context_to_payload($payload);
    }

    $order = wc_get_order($order_id);

    if (! $order) {
        return revenue_leak_detector_add_request_context_to_payload($payload);
    }

    return revenue_leak_detector_add_request_context_to_payload(array_merge(
        $payload,
        array(
            'user_id'              => (int) $order->get_user_id(),
            'status'               => $order->get_status(),
            'currency'             => $order->get_currency(),
            'total'                => (float) $order->get_total(),
            'item_count'           => (int) $order->get_item_count(),
            'payment_method'       => $order->get_payment_method(),
            'payment_method_title' => $order->get_payment_method_title(),
            'shipping_method'      => $order->get_shipping_method(),
            'items'                => revenue_leak_detector_build_order_items_payload($order),
        )
    ));
}

/**
 * Builds the payload for a refund event.
 *
 * @param int $order_id WooCommerce order ID.
 * @param int $refund_id Refund post ID.
 *
 * @return array<string, mixed>
 */
function revenue_leak_detector_build_refund_payload($order_id, $refund_id)
{
    $payload = revenue_leak_detector_build_order_lifecycle_payload($order_id, 'refund');
    $payload['refund_id'] = absint($refund_id);

    if (! function_exists('wc_get_order')) {
        return revenue_leak_detector_add_request_context_to_payload($payload);
    }

    $refund = wc_get_order($refund_id);

    if (! $refund || ! is_a($refund, 'WC_Order_Refund')) {
        return $payload;
    }

    $payload['refund_total'] = (float) abs($refund->get_amount());
    $payload['refund_reason'] = $refund->get_reason();

    return $payload;
}

/**
 * Builds the payload for a payment_success event.
 *
 * @param int $order_id WooCommerce order ID.
 *
 * @return array<string, mixed>
 */
function revenue_leak_detector_build_payment_success_payload($order_id)
{
    $order_id = absint($order_id);
    $payload = array(
        'order_id'    => $order_id,
        'occurred_at' => current_time('mysql', true),
    );

    if (! function_exists('wc_get_order')) {
        return revenue_leak_detector_add_request_context_to_payload($payload);
    }

    $order = wc_get_order($order_id);

    if (! $order) {
        return revenue_leak_detector_add_request_context_to_payload($payload);
    }

    $payload['user_id'] = (int) $order->get_user_id();
    $payload['status'] = $order->get_status();
    $payload['currency'] = $order->get_currency();
    $payload['total'] = (float) $order->get_total();
    $payload['item_count'] = (int) $order->get_item_count();
    $payload['payment_method'] = $order->get_payment_method();
    $payload['payment_method_title'] = $order->get_payment_method_title();
    $payload['shipping_method'] = $order->get_shipping_method();
    $payload['items'] = revenue_leak_detector_build_order_items_payload($order);

    return revenue_leak_detector_add_request_context_to_payload($payload);
}

/**
 * Builds a full API URL from a relative path.
 *
 * @param string $path Relative API path.
 *
 * @return string|WP_Error
 */
function revenue_leak_detector_build_api_url($path)
{
    $base_url = revenue_leak_detector_get_api_base_url();

    if ($base_url === '') {
        return new WP_Error(
            'revenue_leak_detector_missing_api_base_url',
            __('API base URL is not configured.', 'revenue-leak-detector')
        );
    }

    $path = ltrim($path, '/');

    return trailingslashit($base_url) . $path;
}

/**
 * Returns the configured API base URL.
 *
 * Priority:
 * 1. REVENUE_LEAK_DETECTOR_API_BASE_URL constant
 * 2. WordPress option
 * 3. Empty string
 *
 * @return string
 */
function revenue_leak_detector_get_api_base_url()
{
    if (defined('REVENUE_LEAK_DETECTOR_API_BASE_URL')) {
        return untrailingslashit((string) REVENUE_LEAK_DETECTOR_API_BASE_URL);
    }

    $base_url = get_option('revenue_leak_detector_api_base_url', '');

    if (! is_string($base_url) || $base_url === '') {
        return '';
    }

    return untrailingslashit($base_url);
}

/**
 * Sends a POST request to the configured API.
 *
 * @param string $path Relative API path.
 * @param array  $data Request payload.
 * @param array  $args Optional wp_remote_post arguments.
 *
 * @return array|WP_Error
 */
function revenue_leak_detector_api_post($path, array $data, array $args = array())
{
    $url = revenue_leak_detector_build_api_url($path);

    if (is_wp_error($url)) {
        return $url;
    }

    $request_args = wp_parse_args(
        $args,
        array(
            'method'  => 'POST',
            'timeout' => 15,
            'headers' => array(
                'Content-Type' => 'application/json; charset=utf-8',
            ),
            'body'    => wp_json_encode($data),
        )
    );

    if (! is_string($request_args['body']) || $request_args['body'] === '') {
        return new WP_Error(
            'revenue_leak_detector_invalid_request_body',
            __('Request body could not be encoded.', 'revenue-leak-detector')
        );
    }

    return wp_remote_post(esc_url_raw($url), $request_args);
}

/**
 * Sends a GET request to the configured API.
 *
 * @param string $path Relative API path.
 * @param array  $args Optional wp_remote_get arguments.
 *
 * @return array|WP_Error
 */
function revenue_leak_detector_api_get($path, array $args = array())
{
    $url = revenue_leak_detector_build_api_url($path);

    if (is_wp_error($url)) {
        return $url;
    }

    $request_args = wp_parse_args(
        $args,
        array(
            'method'  => 'GET',
            'timeout' => 15,
            'headers' => array(
                'Accept' => 'application/json',
            ),
        )
    );

    return wp_remote_get(esc_url_raw($url), $request_args);
}

/**
 * Decodes a JSON API response.
 *
 * @param array|WP_Error $response HTTP response.
 *
 * @return array|WP_Error
 */
function revenue_leak_detector_decode_api_response($response)
{
    if (is_wp_error($response)) {
        return $response;
    }

    $status_code = (int) wp_remote_retrieve_response_code($response);
    $body = wp_remote_retrieve_body($response);
    $decoded = json_decode($body, true);

    if ($status_code < 200 || $status_code >= 300) {
        return new WP_Error(
            'revenue_leak_detector_api_request_failed',
            __('API request failed.', 'revenue-leak-detector'),
            array(
                'status_code' => $status_code,
                'body'        => $body,
            )
        );
    }

    if (! is_array($decoded)) {
        return new WP_Error(
            'revenue_leak_detector_invalid_api_response',
            __('API response is not valid JSON.', 'revenue-leak-detector')
        );
    }

    return $decoded;
}

/**
 * Sends pending queue events to the API in a single batch.
 *
 * @param int $limit Maximum number of events.
 *
 * @return array|WP_Error
 */
function revenue_leak_detector_send_pending_events_batch($limit = 20)
{
    $reservation = revenue_leak_detector_reserve_pending_queue_events($limit);
    $reservation_status = $reservation['status'];
    $events = $reservation['events'];

    if ($events === array()) {
        return array(
            'sent_count' => 0,
            'event_ids'  => array(),
        );
    }

    $event_ids = array();
    $payload_events = array();

    foreach ($events as $event) {
        $payload = json_decode($event->payload_json, true);

        if (! is_array($payload)) {
            $payload = array(
                'raw_payload' => $event->payload_json,
            );
        }

        $event_ids[] = (int) $event->id;
        $payload_events[] = array(
            'id'         => (int) $event->id,
            'event_type' => $event->event_type,
            'payload'    => $payload,
            'created_at' => $event->created_at,
        );
    }

    $response = revenue_leak_detector_api_post(
        'events/batch',
        array(
            'events' => $payload_events,
        )
    );

    if (is_wp_error($response)) {
        revenue_leak_detector_release_queue_events($event_ids, $reservation_status);
        return $response;
    }

    $response_code = (int) wp_remote_retrieve_response_code($response);

    if ($response_code < 200 || $response_code >= 300) {
        revenue_leak_detector_release_queue_events($event_ids, $reservation_status);
        return new WP_Error(
            'revenue_leak_detector_batch_request_failed',
            __('Batch request failed.', 'revenue-leak-detector'),
            array(
                'status_code' => $response_code,
                'response'    => $response,
            )
        );
    }

    revenue_leak_detector_mark_queue_events_sent($event_ids, $reservation_status);

    return array(
        'sent_count' => count($event_ids),
        'event_ids'  => $event_ids,
    );
}

/**
 * Schedules the recurring WP-Cron event if it is not already registered.
 *
 * @return void
 */
function revenue_leak_detector_schedule_cron()
{
    if (wp_next_scheduled(REVENUE_LEAK_DETECTOR_CRON_HOOK)) {
        return;
    }

    wp_schedule_event(time() + MINUTE_IN_SECONDS, 'hourly', REVENUE_LEAK_DETECTOR_CRON_HOOK);
}

/**
 * Clears the recurring WP-Cron event.
 *
 * @return void
 */
function revenue_leak_detector_clear_cron()
{
    $timestamp = wp_next_scheduled(REVENUE_LEAK_DETECTOR_CRON_HOOK);

    if ($timestamp) {
        wp_unschedule_event($timestamp, REVENUE_LEAK_DETECTOR_CRON_HOOK);
    }
}

/**
 * Runs the batch sender on the WP-Cron schedule.
 *
 * @return void
 */
function revenue_leak_detector_run_scheduled_batch_send()
{
    revenue_leak_detector_send_pending_events_batch();
}

/**
 * Captures WooCommerce add_to_cart events and stores them in the local queue.
 *
 * @param string $cart_item_key Cart item key.
 * @param int    $product_id    Product ID.
 * @param int    $quantity      Added quantity.
 *
 * @return void
 */
function revenue_leak_detector_capture_add_to_cart($cart_item_key, $product_id, $quantity)
{
    if (! function_exists('WC')) {
        return;
    }

    $classification = revenue_leak_detector_classify_add_to_cart_request($product_id);
    $payload = revenue_leak_detector_build_add_to_cart_payload($product_id, $quantity);

    if ($classification['reasons'] !== array()) {
        $payload['ignored_reasons'] = $classification['reasons'];
    }

    revenue_leak_detector_insert_queue_event(
        'add_to_cart',
        $payload,
        $classification['status']
    );
}

/**
 * Captures cart page views as view_cart events.
 *
 * @return void
 */
function revenue_leak_detector_capture_view_cart()
{
    if (! function_exists('is_cart') || ! is_cart()) {
        return;
    }

    if (! revenue_leak_detector_should_capture_view_cart()) {
        return;
    }

    $classification = revenue_leak_detector_classify_funnel_request();
    $payload = revenue_leak_detector_build_view_cart_payload();

    if ($classification['reasons'] !== array()) {
        $payload['ignored_reasons'] = $classification['reasons'];
    }

    revenue_leak_detector_insert_queue_event(
        'view_cart',
        $payload,
        $classification['status']
    );

    revenue_leak_detector_mark_view_cart_captured();
}

/**
 * Captures remove_from_cart events.
 *
 * @param string  $cart_item_key Cart item key.
 * @param WC_Cart $cart WooCommerce cart instance.
 *
 * @return void
 */
function revenue_leak_detector_capture_remove_from_cart($cart_item_key, $cart)
{
    $removed_item = is_object($cart) && method_exists($cart, 'get_removed_cart_contents')
        ? $cart->get_removed_cart_contents()
        : array();

    if (! isset($removed_item[$cart_item_key])) {
        return;
    }

    $item = $removed_item[$cart_item_key];
    $product_id = isset($item['product_id']) ? absint($item['product_id']) : 0;
    $quantity = isset($item['quantity']) ? absint($item['quantity']) : 1;

    revenue_leak_detector_insert_queue_event(
        'remove_from_cart',
        revenue_leak_detector_build_remove_from_cart_payload($product_id, $quantity)
    );
}

/**
 * Captures checkout page views as begin_checkout events.
 *
 * @return void
 */
function revenue_leak_detector_capture_begin_checkout()
{
    if ((! revenue_leak_detector_is_checkout_request() && ! revenue_leak_detector_is_checkout_pay_request()) || revenue_leak_detector_is_order_received_request()) {
        return;
    }

    if (! revenue_leak_detector_should_capture_begin_checkout()) {
        return;
    }

    $classification = revenue_leak_detector_classify_funnel_request();
    $payload = revenue_leak_detector_build_begin_checkout_payload();

    if ($classification['reasons'] !== array()) {
        $payload['ignored_reasons'] = $classification['reasons'];
    }

    revenue_leak_detector_insert_queue_event(
        'begin_checkout',
        $payload,
        $classification['status']
    );

    revenue_leak_detector_mark_begin_checkout_captured();
}

/**
 * Captures begin_checkout when WooCommerce renders the checkout form.
 *
 * @return void
 */
function revenue_leak_detector_capture_begin_checkout_from_checkout_form()
{
    revenue_leak_detector_capture_begin_checkout();
}

/**
 * Captures successful payment events from the thank-you route.
 *
 * @return void
 */
function revenue_leak_detector_capture_payment_success_from_request()
{
    if (! revenue_leak_detector_is_order_received_request()) {
        return;
    }

    $order_id = absint(get_query_var('order-received'));

    if ($order_id <= 0 && isset($_GET['order-received'])) {
        $order_id = absint($_GET['order-received']);
    }

    if ($order_id > 0) {
        revenue_leak_detector_capture_payment_success($order_id);
    }
}

/**
 * Captures successful WooCommerce payments and stores them in the local queue.
 *
 * @param int $order_id WooCommerce order ID.
 *
 * @return void
 */
function revenue_leak_detector_capture_payment_success($order_id)
{
    if (! function_exists('wc_get_order')) {
        return;
    }

    $order = wc_get_order($order_id);

    if (! $order) {
        return;
    }

    $already_tracked = $order->get_meta('_revenue_leak_detector_payment_success_tracked', true);

    if ($already_tracked) {
        return;
    }

    $classification = revenue_leak_detector_classify_order_lifecycle_request();

    if ($classification['status'] === 'ignored' && $order->get_meta('_revenue_leak_detector_payment_success_ignored_tracked', true)) {
        return;
    }

    revenue_leak_detector_insert_classified_queue_event(
        'payment_success',
        revenue_leak_detector_build_payment_success_payload($order_id),
        $classification
    );

    if ($classification['status'] === 'pending') {
        $order->update_meta_data('_revenue_leak_detector_payment_success_tracked', 1);
        $order->save();
        return;
    }

    $order->update_meta_data('_revenue_leak_detector_payment_success_ignored_tracked', 1);
    $order->save();
}

/**
 * Captures checkout info submission events once an order is created.
 *
 * @param int      $order_id WooCommerce order ID.
 * @param array    $posted_data Checkout posted data.
 * @param WC_Order $order WooCommerce order.
 *
 * @return void
 */
function revenue_leak_detector_capture_checkout_info_events($order_id, $posted_data, $order)
{
    if (! $order || ! is_a($order, 'WC_Order')) {
        return;
    }

    if (! $order->get_meta('_revenue_leak_detector_add_shipping_info_tracked', true)) {
        revenue_leak_detector_insert_queue_event(
            'add_shipping_info',
            revenue_leak_detector_build_add_shipping_info_payload($order)
        );
        $order->update_meta_data('_revenue_leak_detector_add_shipping_info_tracked', 1);
    }

    if (! $order->get_meta('_revenue_leak_detector_add_payment_info_tracked', true)) {
        revenue_leak_detector_insert_queue_event(
            'add_payment_info',
            revenue_leak_detector_build_add_payment_info_payload($order)
        );
        $order->update_meta_data('_revenue_leak_detector_add_payment_info_tracked', 1);
    }

    $order->save();
}

/**
 * Captures order failure events.
 *
 * @param int $order_id WooCommerce order ID.
 *
 * @return void
 */
function revenue_leak_detector_capture_order_failed($order_id)
{
    revenue_leak_detector_insert_queue_event(
        'order_failed',
        revenue_leak_detector_build_order_lifecycle_payload($order_id, 'order_failed')
    );
}

/**
 * Captures order cancellation events.
 *
 * @param int $order_id WooCommerce order ID.
 *
 * @return void
 */
function revenue_leak_detector_capture_order_cancelled($order_id)
{
    revenue_leak_detector_insert_queue_event(
        'order_cancelled',
        revenue_leak_detector_build_order_lifecycle_payload($order_id, 'order_cancelled')
    );
}

/**
 * Captures refund events.
 *
 * @param int $order_id WooCommerce order ID.
 * @param int $refund_id Refund post ID.
 *
 * @return void
 */
function revenue_leak_detector_capture_refund($order_id, $refund_id)
{
    revenue_leak_detector_insert_queue_event(
        'refund',
        revenue_leak_detector_build_refund_payload($order_id, $refund_id)
    );
}

/**
 * Registers the plugin admin page.
 *
 * @return void
 */
function revenue_leak_detector_register_admin_menu()
{
    add_menu_page(
        __('Revenue Leak Detector', 'revenue-leak-detector'),
        __('Revenue Leak Detector', 'revenue-leak-detector'),
        'manage_options',
        'revenue-leak-detector',
        'revenue_leak_detector_render_admin_page',
        'dashicons-chart-area',
        56
    );
}

/**
 * Renders a dashboard section.
 *
 * @param string            $title Section title.
 * @param array|WP_Error    $data  Section data.
 *
 * @return void
 */
function revenue_leak_detector_render_dashboard_section($title, $data)
{
    echo '<div class="postbox" style="padding:16px; margin-top:16px;">';
    echo '<h2 style="margin-top:0;">' . esc_html($title) . '</h2>';

    if (is_wp_error($data)) {
        echo '<p>' . esc_html($data->get_error_message()) . '</p>';
        echo '</div>';
        return;
    }

    if ($data === array()) {
        echo '<p>' . esc_html__('No data available.', 'revenue-leak-detector') . '</p>';
        echo '</div>';
        return;
    }

    echo '<table class="widefat striped"><tbody>';

    foreach ($data as $key => $value) {
        echo '<tr>';
        echo '<td style="width:220px;"><strong>' . esc_html((string) $key) . '</strong></td>';

        if (is_array($value)) {
            echo '<td><pre style="margin:0; white-space:pre-wrap;">' . esc_html(wp_json_encode($value, JSON_PRETTY_PRINT)) . '</pre></td>';
        } else {
            echo '<td>' . esc_html((string) $value) . '</td>';
        }

        echo '</tr>';
    }

    echo '</tbody></table>';
    echo '</div>';
}

/**
 * Renders the issues section.
 *
 * @param array|WP_Error $issues Issues payload.
 *
 * @return void
 */
function revenue_leak_detector_render_issues_section($issues)
{
    echo '<div class="postbox" style="padding:16px; margin-top:16px;">';
    echo '<h2 style="margin-top:0;">' . esc_html__('Issues', 'revenue-leak-detector') . '</h2>';

    if (is_wp_error($issues)) {
        echo '<p>' . esc_html($issues->get_error_message()) . '</p>';
        echo '</div>';
        return;
    }

    if ($issues === array()) {
        echo '<p>' . esc_html__('No issues available.', 'revenue-leak-detector') . '</p>';
        echo '</div>';
        return;
    }

    echo '<table class="widefat striped"><thead><tr>';
    echo '<th>' . esc_html__('Issue', 'revenue-leak-detector') . '</th>';
    echo '<th>' . esc_html__('Details', 'revenue-leak-detector') . '</th>';
    echo '</tr></thead><tbody>';

    foreach ($issues as $key => $value) {
        echo '<tr>';
        echo '<td>' . esc_html(is_string($key) ? $key : __('Item', 'revenue-leak-detector')) . '</td>';

        if (is_array($value)) {
            echo '<td><pre style="margin:0; white-space:pre-wrap;">' . esc_html(wp_json_encode($value, JSON_PRETTY_PRINT)) . '</pre></td>';
        } else {
            echo '<td>' . esc_html((string) $value) . '</td>';
        }

        echo '</tr>';
    }

    echo '</tbody></table>';
    echo '</div>';
}

/**
 * Renders local dashboard styles.
 *
 * @return void
 */
function revenue_leak_detector_render_local_dashboard_styles()
{
    echo '<style>
    .rld-tabs{display:flex; gap:8px; margin:18px 0 0;}
    .rld-tab{display:inline-flex; align-items:center; padding:10px 14px; border-radius:999px; border:1px solid #cbd5e1; background:#fff; color:#334155; text-decoration:none; font-weight:600;}
    .rld-tab-active{background:#0f172a; color:#fff; border-color:#0f172a;}
    .rld-subtabs{display:flex; gap:8px; flex-wrap:wrap; margin:0 0 16px;}
    .rld-subtab{display:inline-flex; align-items:center; padding:8px 12px; border-radius:999px; border:1px solid #dbe3ec; background:#fff; color:#475569; text-decoration:none; font-weight:600; font-size:13px;}
    .rld-subtab-active{background:#eff6ff; color:#1d4ed8; border-color:#bfdbfe;}
    .rld-presets{display:flex; gap:8px; flex-wrap:wrap; margin-top:14px;}
    .rld-preset{display:inline-flex; align-items:center; padding:8px 12px; border-radius:999px; border:1px solid rgba(255,255,255,.18); background:rgba(255,255,255,.08); color:#fff; text-decoration:none; font-weight:600; font-size:12px;}
    .rld-preset-active{background:#fff; color:#0f172a; border-color:#fff;}
    .rld-shell{margin-top:16px;}
    .rld-panel{background:linear-gradient(180deg,#ffffff 0%,#f8fafc 100%); border:1px solid #dbe3ec; border-radius:20px; box-shadow:0 16px 40px rgba(15,23,42,.06); padding:20px;}
    .rld-hero{display:flex; justify-content:space-between; gap:18px; align-items:flex-end; margin-bottom:14px; background:linear-gradient(135deg,#0f172a 0%,#1d4ed8 62%,#14b8a6 100%); color:#fff; border-radius:24px; padding:22px 24px;}
    .rld-hero h2{margin:0 0 6px; color:#fff; font-size:26px; line-height:1.08;}
    .rld-hero p{margin:0; color:rgba(255,255,255,.82); max-width:620px; font-size:14px; line-height:1.45;}
    .rld-hero-meta{display:grid; gap:8px; min-width:320px; max-width:460px;}
    .rld-hero-pill{font-size:12px; letter-spacing:.08em; text-transform:uppercase; color:rgba(255,255,255,.74);}
    .rld-top-issue{background:rgba(255,255,255,.16); border:1px solid rgba(255,255,255,.2); border-radius:20px; padding:16px; box-shadow:0 12px 30px rgba(15,23,42,.18);}
    .rld-top-issue strong{display:block; font-size:21px; color:#fff; margin:8px 0 6px; line-height:1.15;}
    .rld-top-issue span{color:rgba(255,255,255,.86);}
    .rld-top-issue-impact{display:block; margin-top:8px; font-size:13px; color:#fff;}
    .rld-top-issue-action{display:block; margin-top:10px; padding-top:10px; border-top:1px solid rgba(255,255,255,.14); font-size:13px; color:#fff;}
    .rld-top-issue .rld-hero-severity{display:inline-flex; align-items:center; padding:6px 10px; border-radius:999px; background:#fff; color:#0f172a; font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:.08em;}
    .rld-top-issue .rld-top-issue-loss{display:inline-flex; align-items:center; margin-top:10px; padding:8px 12px; border-radius:999px; background:#fff; color:#991b1b; font-size:12px; font-weight:800;}
    .rld-filterbar{display:flex; flex-wrap:wrap; gap:12px; align-items:end; margin:14px 0 0;}
    .rld-field{display:flex; flex-direction:column; gap:6px;}
    .rld-field label{font-size:12px; font-weight:600; color:#475569;}
    .rld-hero .rld-field label{color:rgba(255,255,255,.82);}
    .rld-field input{min-width:180px; border:1px solid #cbd5e1; border-radius:10px; padding:8px 10px;}
    .rld-hero .rld-field input{border-color:rgba(255,255,255,.18); background:rgba(255,255,255,.1); color:#fff;}
    .rld-hero .rld-field input::-webkit-calendar-picker-indicator{filter:invert(1);}
    .rld-filter-actions{display:flex; gap:8px; align-items:center;}
    .rld-hero .rld-filter-actions .button{display:inline-flex; align-items:center; justify-content:center; min-height:40px; padding:0 16px; border-radius:12px; border-color:rgba(255,255,255,.18); box-shadow:none; text-shadow:none; font-weight:700; line-height:1;}
    .rld-hero .rld-filter-actions .button-primary{background:linear-gradient(135deg,#ffffff 0%,#eff6ff 100%); color:#0f172a; border-color:#ffffff;}
    .rld-hero .rld-filter-actions .button-primary:hover,.rld-hero .rld-filter-actions .button-primary:focus{background:linear-gradient(135deg,#ffffff 0%,#dbeafe 100%); color:#0f172a; border-color:#ffffff;}
    .rld-hero .rld-filter-actions .button-secondary{background:rgba(255,255,255,.12); color:#fff;}
    .rld-hero .rld-filter-actions .button-secondary:hover,.rld-hero .rld-filter-actions .button-secondary:focus{background:rgba(255,255,255,.18); color:#fff; border-color:rgba(255,255,255,.28);}
    .rld-grid{display:grid; grid-template-columns:repeat(auto-fit,minmax(230px,1fr)); gap:14px; margin-top:14px;}
    .rld-card{position:relative; overflow:hidden; background:#fff; border:1px solid #e2e8f0; border-radius:18px; padding:16px; box-shadow:0 8px 24px rgba(15,23,42,.05); transition:transform .18s ease, box-shadow .18s ease, border-color .18s ease;}
    .rld-card-has-tooltip{overflow:visible; z-index:2;}
    .rld-card::after{content:""; position:absolute; inset:auto -20px -40px auto; width:100px; height:100px; background:radial-gradient(circle,#dbeafe 0%,rgba(219,234,254,0) 70%);}
    .rld-card-problem{border-color:#fca5a5; background:linear-gradient(180deg,#fff7f7 0%,#fff 100%);}
    .rld-card-problem::after{background:radial-gradient(circle,#fee2e2 0%,rgba(254,226,226,0) 70%);}
    .rld-label{font-size:12px; letter-spacing:.08em; text-transform:uppercase; color:#64748b; margin-bottom:8px; display:inline-flex; align-items:center; gap:6px;}
    .rld-tooltip{position:relative; display:inline-flex; align-items:center;}
    .rld-tooltip-trigger{display:inline-flex; align-items:center; justify-content:center; width:18px; height:18px; border:none; border-radius:999px; padding:0; background:#eff6ff; color:#1d4ed8; cursor:help;}
    .rld-tooltip-trigger .rld-icon{width:12px; height:12px; flex-basis:12px;}
    .rld-tooltip-content{position:absolute; left:50%; top:calc(100% + 10px); transform:translateX(-50%); width:260px; padding:10px 12px; border-radius:12px; background:#0f172a; color:#e2e8f0; font-size:12px; line-height:1.5; text-transform:none; letter-spacing:normal; box-shadow:0 14px 28px rgba(15,23,42,.22); opacity:0; visibility:hidden; pointer-events:none; transition:opacity .18s ease, visibility .18s ease, transform .18s ease; z-index:20;}
    .rld-tooltip-content::after{content:""; position:absolute; bottom:100%; left:50%; transform:translateX(-50%); border:6px solid transparent; border-bottom-color:#0f172a;}
    .rld-tooltip:hover .rld-tooltip-content,.rld-tooltip:focus-within .rld-tooltip-content{opacity:1; visibility:visible; transform:translateX(-50%) translateY(2px);}
    .rld-tooltip-content strong{display:block; color:#fff; margin-bottom:6px; font-size:12px;}
    .rld-value{font-size:32px; font-weight:700; color:#0f172a; line-height:1;}
    .rld-value-compact{font-size:24px; line-height:1.15;}
    .rld-kpi-stack{display:grid; gap:4px;}
    .rld-kpi-stack-top{font-size:13px; font-weight:700; letter-spacing:.06em; text-transform:uppercase; color:#991b1b;}
    .rld-kpi-stack-main{font-size:24px; font-weight:800; color:#0f172a; line-height:1.2;}
    .rld-kpi-stack-bottom{font-size:16px; font-weight:700; color:#991b1b; line-height:1.25;}
    .rld-subtle{font-size:13px; color:#64748b; margin-top:6px; line-height:1.45;}
    .rld-subtle-strong{font-size:14px; color:#991b1b; font-weight:700; margin-top:8px;}
    .rld-event-key{display:block; margin-top:4px; font-size:12px; color:#64748b; font-weight:500;}
    .rld-two-col{display:grid; grid-template-columns:minmax(0,1.35fr) minmax(320px,1fr); gap:16px; margin-top:16px;}
    .rld-section-title{margin:0 0 14px; font-size:18px; color:#0f172a;}
    .rld-summary-grid{display:grid; grid-template-columns:minmax(0,.98fr) minmax(360px,1fr); gap:16px; margin-top:14px; align-items:start;}
    .rld-side-stack{display:grid; gap:16px; align-content:start;}
    .rld-next-action{margin-top:0; display:grid; grid-template-columns:minmax(0,1.3fr) 180px; gap:14px; align-items:center; border:1px solid #bfdbfe; background:linear-gradient(180deg,#ffffff 0%,#f8fbff 100%); border-radius:20px; padding:18px 18px; box-shadow:0 12px 28px rgba(15,23,42,.05); transition:transform .18s ease, box-shadow .18s ease, border-color .18s ease;}
    .rld-icon{display:inline-flex; width:16px; height:16px; flex:0 0 16px; color:currentColor; vertical-align:middle;}
    .rld-icon svg{width:100%; height:100%; stroke:currentColor; fill:none; stroke-width:1.9; stroke-linecap:round; stroke-linejoin:round;}
    .rld-icon-lg{width:20px; height:20px; flex-basis:20px;}
    .rld-inline-icon{display:inline-flex; align-items:center; gap:8px;}
    .rld-icon-loss{color:#be123c;}
    .rld-icon-success{color:#5b7b68;}
    .rld-icon-action{color:#1d4ed8;}
    .rld-icon-warning{color:#92400e;}
    .rld-next-action-label{display:flex; align-items:center; gap:8px; font-size:12px; letter-spacing:.08em; text-transform:uppercase; color:#64748b; line-height:1;}
    .rld-next-action-label .rld-inline-icon{display:inline-flex; align-items:center;}
    .rld-next-action-label .rld-tooltip{display:inline-flex; align-items:center; transform:none;}
    .rld-next-action-title{font-size:22px; font-weight:700; color:#0f172a; line-height:1.2; margin-top:4px;}
    .rld-next-action-summary{margin-top:10px; color:#334155; font-size:14px; line-height:1.45;}
    .rld-next-action-reason{margin-top:10px; padding:10px 12px; border-radius:14px; background:#eff6ff; color:#0f172a; font-size:13px; font-weight:600; line-height:1.45;}
    .rld-next-action-list{margin:12px 0 0; padding:0; list-style:none; display:grid; gap:8px;}
    .rld-next-action-list li{display:flex; gap:8px; align-items:flex-start; color:#334155; font-size:14px; line-height:1.45;}
    .rld-next-action-list li .rld-icon{margin-top:2px;}
    .rld-next-action-meta{display:grid; gap:8px; justify-items:end;}
    .rld-next-action-pill{display:inline-flex; padding:8px 12px; border-radius:999px; background:#eff6ff; color:#1d4ed8; font-size:12px; font-weight:700;}
    .rld-funnel-flow{display:grid; grid-template-columns:1fr; gap:12px; align-items:stretch; max-width:640px; margin:0 auto;}
    .rld-funnel-step{background:#fff; border:1px solid #e2e8f0; border-radius:18px; padding:15px; position:relative; transition:transform .18s ease, box-shadow .18s ease, border-color .18s ease;}
    .rld-funnel-step-primary{box-shadow:0 12px 24px rgba(15,23,42,.06);}
    .rld-funnel-connector{display:grid; gap:6px; justify-items:center; text-align:center;}
    .rld-funnel-arrow{font-size:30px; color:#94a3b8; line-height:1; transform:rotate(90deg); text-align:center;}
    .rld-funnel-connector-card{width:100%; max-width:560px; margin:0 auto; background:linear-gradient(180deg,#fff5f5 0%,#fff 100%); border:1px solid #fca5a5; border-radius:16px; padding:14px 12px; box-shadow:0 10px 22px rgba(190,24,93,.08); transition:transform .18s ease, box-shadow .18s ease, border-color .18s ease;}
    .rld-funnel-connector-card-ok{background:linear-gradient(180deg,#f0fdf4 0%,#fff 100%); border-color:#86efac; box-shadow:0 10px 22px rgba(4,120,87,.06);}
    .rld-funnel-connector-label{font-size:11px; text-transform:uppercase; letter-spacing:.08em; color:#64748b; display:inline-flex; align-items:center; justify-content:center; gap:6px;}
    .rld-funnel-connector-heading{display:flex; justify-content:center; margin-bottom:2px;}
    .rld-funnel-connector-value{font-size:27px; font-weight:900; color:#991b1b; margin-top:4px; line-height:1;}
    .rld-funnel-connector-card-ok .rld-funnel-connector-value{color:#047857;}
    .rld-funnel-connector-loss{font-size:20px; font-weight:900; color:#0f172a; margin-top:4px; display:inline-flex; align-items:center; justify-content:center; gap:8px;}
    .rld-funnel-connector-sub{font-size:12px; color:#475569; margin-top:4px;}
    .rld-step-label{font-size:12px; text-transform:uppercase; letter-spacing:.08em; color:#64748b; display:inline-flex; align-items:center; gap:8px;}
    .rld-step-count{font-size:28px; font-weight:700; color:#0f172a; margin-top:8px;}
    .rld-step-meta{display:grid; gap:4px; margin-top:8px; font-size:13px; color:#475569; line-height:1.45; justify-items:start;}
    .rld-step-dropoff{display:inline-flex; align-items:center; justify-self:start; gap:6px; margin-top:10px; padding:7px 10px; border-radius:999px; background:#fff1f2; color:#be123c; font-size:12px; font-weight:700;}
    .rld-step-dropoff-ok{background:#ecfdf5; color:#047857;}
    .rld-issues{display:grid; gap:12px;}
    .rld-issue{border:1px solid #e2e8f0; border-radius:18px; padding:15px; background:#fff; transition:transform .18s ease, box-shadow .18s ease, border-color .18s ease;}
    .rld-issue-high{border-color:#fca5a5; background:linear-gradient(180deg,#fff7f7 0%,#fff 100%); box-shadow:0 10px 22px rgba(190,24,93,.06);}
    .rld-issue-medium{border-color:#fde68a; background:linear-gradient(180deg,#fffbeb 0%,#fff 100%);}
    .rld-issue-low{border-color:#bfdbfe; background:linear-gradient(180deg,#eff6ff 0%,#fff 100%);}
    .rld-severity{display:inline-flex; align-items:center; gap:6px; padding:5px 10px; border-radius:999px; font-size:11px; font-weight:700; letter-spacing:.08em; text-transform:uppercase; margin-bottom:12px;}
    .rld-severity-high{background:#fee2e2; color:#991b1b;}
    .rld-severity-medium{background:#fef3c7; color:#92400e;}
    .rld-severity-low{background:#dbeafe; color:#1d4ed8;}
    .rld-issue h3{margin:0 0 8px; font-size:18px; color:#0f172a;}
    .rld-issue p{margin:0; color:#475569;}
    .rld-issue-impact{margin-top:10px; padding:10px 12px; border-radius:14px; background:#f8fafc; color:#0f172a; font-size:13px; font-weight:700;}
    .rld-issue-lost{display:inline-flex; margin-top:10px; padding:7px 10px; border-radius:999px; background:#fff; border:1px solid #fecaca; color:#991b1b; font-size:12px; font-weight:800;}
    .rld-issue-action{margin-top:12px; padding-top:12px; border-top:1px solid #e2e8f0; font-size:13px;}
    .rld-issue-action strong{color:#0f172a;}
    .rld-bar{height:10px; background:#e2e8f0; border-radius:999px; overflow:hidden;}
    .rld-bar > span{display:block; height:100%; border-radius:999px; background:linear-gradient(90deg,#0ea5e9 0%,#2563eb 100%);}
    .rld-chip-list{display:flex; flex-wrap:wrap; gap:8px;}
    .rld-chip{display:inline-flex; align-items:center; gap:6px; padding:8px 10px; border-radius:999px; background:#eff6ff; color:#1d4ed8; font-size:12px; font-weight:600;}
    .rld-chip strong{color:#0f172a;}
    .rld-chart-card{margin-top:14px;}
    .rld-chart-wrap{background:#fff; border:1px solid #e2e8f0; border-radius:18px; padding:14px 16px;}
    .rld-chart-summary{margin:0 0 12px; color:#475569; font-size:14px; line-height:1.45;}
    .rld-chart-legend{display:flex; gap:16px; flex-wrap:wrap; margin-bottom:14px; font-size:13px; color:#475569;}
    .rld-trend-metrics{display:flex; gap:10px; flex-wrap:wrap; margin-bottom:14px;}
    .rld-chart-key{display:inline-flex; align-items:center; gap:8px;}
    .rld-chart-dot{width:10px; height:10px; border-radius:999px; display:inline-block;}
    .rld-chart-axis{font-size:11px; fill:#64748b;}
    .rld-chart-line-cart{stroke:#0ea5e9; fill:none; stroke-width:3;}
    .rld-chart-line-purchase{stroke:#22c55e; fill:none; stroke-width:3;}
    .rld-chart-area{fill:rgba(14,165,233,.08);}
    .rld-settings-note{margin-top:10px; color:#64748b;}
    @media (hover: hover){
        .rld-card:hover,.rld-card:focus-within{transform:translateY(-2px); box-shadow:0 14px 32px rgba(15,23,42,.08); border-color:#cbd5e1;}
        .rld-next-action:hover,.rld-next-action:focus-within{transform:translateY(-2px); box-shadow:0 16px 34px rgba(15,23,42,.08); border-color:#93c5fd;}
        .rld-funnel-step:hover,.rld-funnel-step:focus-within{transform:translateY(-2px); box-shadow:0 16px 30px rgba(15,23,42,.08); border-color:#cbd5e1;}
        .rld-funnel-connector-card:hover,.rld-funnel-connector-card:focus-within{transform:translateY(-2px); box-shadow:0 14px 28px rgba(190,24,93,.12); border-color:#fb7185;}
        .rld-funnel-connector-card-ok:hover,.rld-funnel-connector-card-ok:focus-within{box-shadow:0 14px 28px rgba(4,120,87,.1); border-color:#4ade80;}
        .rld-issue:hover,.rld-issue:focus-within{transform:translateY(-2px); box-shadow:0 14px 28px rgba(15,23,42,.07); border-color:#cbd5e1;}
        .rld-issue-high:hover,.rld-issue-high:focus-within{border-color:#fb7185;}
    }
    @media (max-width: 960px){.rld-two-col,.rld-summary-grid,.rld-next-action{grid-template-columns:1fr;}.rld-hero{flex-direction:column; align-items:flex-start; padding:20px;}.rld-hero-meta{min-width:0; width:100%; max-width:none;}.rld-next-action-meta{justify-items:start;}.rld-funnel-connector-card,.rld-funnel-step{width:100%;}}
    </style>';
}

/**
 * Returns the active admin tab.
 *
 * @return string
 */
function revenue_leak_detector_get_admin_tab()
{
    $tab = isset($_GET['tab']) ? sanitize_key(wp_unslash($_GET['tab'])) : 'dashboard';

    if (! in_array($tab, array('dashboard', 'settings'), true)) {
        return 'dashboard';
    }

    if ($tab === 'settings' && ! revenue_leak_detector_should_show_developer_settings()) {
        return 'dashboard';
    }

    return $tab;
}

/**
 * Renders top-level admin tabs.
 *
 * @param string $active_tab Active tab key.
 *
 * @return void
 */
function revenue_leak_detector_render_admin_tabs($active_tab)
{
    $dashboard_url = add_query_arg(
        array(
            'page' => 'revenue-leak-detector',
            'tab'  => 'dashboard',
        ),
        admin_url('admin.php')
    );
    echo '<div class="rld-tabs">';
    echo '<a class="rld-tab ' . esc_attr($active_tab === 'dashboard' ? 'rld-tab-active' : '') . '" href="' . esc_url($dashboard_url) . '">' . esc_html__('Dashboard', 'revenue-leak-detector') . '</a>';
    if (revenue_leak_detector_should_show_developer_settings()) {
        $settings_url = add_query_arg(
            array(
                'page' => 'revenue-leak-detector',
                'tab'  => 'settings',
            ),
            admin_url('admin.php')
        );
        echo '<a class="rld-tab ' . esc_attr($active_tab === 'settings' ? 'rld-tab-active' : '') . '" href="' . esc_url($settings_url) . '">' . esc_html__('Settings', 'revenue-leak-detector') . '</a>';
    }
    echo '</div>';
}

/**
 * Renders quick date preset links.
 *
 * @param array{start_date: string, end_date: string, preset: string} $filters Date filters.
 *
 * @return void
 */
function revenue_leak_detector_render_date_presets(array $filters)
{
    $presets = array(
        'today' => __('Today', 'revenue-leak-detector'),
        'yesterday' => __('Yesterday', 'revenue-leak-detector'),
        '7d'    => __('Last 7 Days', 'revenue-leak-detector'),
        '14d'   => __('Last 14 Days', 'revenue-leak-detector'),
        '30d'   => __('Last 30 Days', 'revenue-leak-detector'),
    );

    echo '<div class="rld-presets">';

    foreach ($presets as $preset_key => $label) {
        $url = add_query_arg(
            array(
                'page'   => 'revenue-leak-detector',
                'tab'    => 'dashboard',
                'preset' => $preset_key,
            ),
            admin_url('admin.php')
        );
        echo '<a class="rld-preset ' . esc_attr($filters['preset'] === $preset_key ? 'rld-preset-active' : '') . '" href="' . esc_url($url) . '">' . esc_html($label) . '</a>';
    }

    echo '</div>';
}

/**
 * Returns a human-readable label for an event key.
 *
 * @param string $event_type Event key.
 *
 * @return string
 */
function revenue_leak_detector_get_event_label($event_type)
{
    $labels = array(
        'view_cart'         => __('Cart Viewed', 'revenue-leak-detector'),
        'add_to_cart'       => __('Product Added to Cart', 'revenue-leak-detector'),
        'remove_from_cart'  => __('Product Removed from Cart', 'revenue-leak-detector'),
        'begin_checkout'    => __('Checkout Started', 'revenue-leak-detector'),
        'add_shipping_info' => __('Shipping Info Submitted', 'revenue-leak-detector'),
        'add_payment_info'  => __('Payment Info Submitted', 'revenue-leak-detector'),
        'payment_success'   => __('Payment Successful', 'revenue-leak-detector'),
        'order_failed'      => __('Order Failed', 'revenue-leak-detector'),
        'order_cancelled'   => __('Order Cancelled', 'revenue-leak-detector'),
        'refund'            => __('Refund Issued', 'revenue-leak-detector'),
        'test_event'        => __('Test Event', 'revenue-leak-detector'),
    );

    if (isset($labels[$event_type])) {
        return $labels[$event_type];
    }

    return ucwords(str_replace('_', ' ', (string) $event_type));
}

/**
 * Returns a translated severity label.
 *
 * @param string $severity Severity key.
 *
 * @return string
 */
function revenue_leak_detector_get_severity_label($severity)
{
    $labels = array(
        'high'   => __('High', 'revenue-leak-detector'),
        'medium' => __('Medium', 'revenue-leak-detector'),
        'low'    => __('Low', 'revenue-leak-detector'),
    );

    return isset($labels[$severity]) ? $labels[$severity] : ucfirst((string) $severity);
}

/**
 * Returns a minimal inline SVG icon.
 *
 * @param string $icon  Icon key.
 * @param string $class Optional wrapper class.
 *
 * @return string
 */
function revenue_leak_detector_get_icon_svg($icon, $class = '')
{
    $paths = array(
        'cart' => '<path d="M2.5 3.5h2l1.4 7h9.3l1.8-5.5H6.2"/><circle cx="9" cy="17" r="1.4"/><circle cx="15.5" cy="17" r="1.4"/>',
        'checkout' => '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 8h10M7 12h6M15.5 15.5l1.5 1.5 3-3"/>',
        'success' => '<circle cx="12" cy="12" r="9"/><path d="m8.5 12 2.3 2.3 4.7-5.1"/>',
        'loss' => '<path d="M12 3v10"/><path d="m8.5 10.5 3.5 3.5 3.5-3.5"/><path d="M5 19h14"/>',
        'action' => '<path d="M12 3.5 14.7 9l5.8.8-4.2 4.1 1 5.8L12 16.9 6.7 19.7l1-5.8-4.2-4.1L9.3 9z"/>',
        'warning' => '<path d="M12 4.5 20 18H4z"/><path d="M12 9v4.5"/><circle cx="12" cy="16.2" r=".8"/>',
        'info' => '<circle cx="12" cy="12" r="9"/><path d="M12 10.5v5"/><circle cx="12" cy="7.8" r=".8"/>',
    );

    if (! isset($paths[$icon])) {
        return '';
    }

    $wrapper_class = trim('rld-icon ' . $class);

    return '<span class="' . esc_attr($wrapper_class) . '" aria-hidden="true"><svg viewBox="0 0 24 24" focusable="false">' . $paths[$icon] . '</svg></span>';
}

/**
 * Formats a decimal ratio as percentage text.
 *
 * @param float $value Ratio between 0 and 1.
 *
 * @return string
 */
function revenue_leak_detector_format_percent($value)
{
    return round(((float) $value) * 100, 1) . '%';
}

/**
 * Returns the revenue leak score tooltip text.
 *
 * @return string
 */
function revenue_leak_detector_get_leak_score_tooltip()
{
    return __('Score starts from 100 and decreases based on funnel leakage. Weights: checkout abandonment 55%, cart-to-purchase loss 25%, order failures 12%, refunds 8%. Higher is healthier.', 'revenue-leak-detector');
}

/**
 * Returns HTML for a reusable info tooltip trigger.
 *
 * @param string $title   Tooltip title.
 * @param string $content Tooltip body.
 *
 * @return string
 */
function revenue_leak_detector_render_info_tooltip($title, $content)
{
    return '<span class="rld-tooltip"><button type="button" class="rld-tooltip-trigger" aria-label="' . esc_attr($title) . '">' . revenue_leak_detector_get_icon_svg('info') . '</button><span class="rld-tooltip-content"><strong>' . esc_html($title) . '</strong>' . esc_html($content) . '</span></span>';
}

/**
 * Returns concise action bullets for the next action card.
 *
 * @param array<string, mixed> $top_issue Top issue payload.
 *
 * @return array<int, string>
 */
function revenue_leak_detector_get_next_action_items(array $top_issue)
{
    $title = isset($top_issue['title']) ? (string) $top_issue['title'] : '';

    if (strpos($title, 'Checkout') !== false && strpos($title, 'Abandonment') !== false) {
        return array(
            __('Checkout alanındaki dikkat dağıtıcı adımları kaldırın.', 'revenue-leak-detector'),
            __('Formu kısaltın ve ödeme adımındaki sürtünmeyi azaltın.', 'revenue-leak-detector'),
            __('Başarısız ödeme veya validasyon hatalarını inceleyin.', 'revenue-leak-detector'),
        );
    }

    if (strpos($title, 'Cart') !== false || strpos($title, 'Sepet') !== false) {
        return array(
            __('Sepet sayfasındaki checkout CTA görünürlüğünü artırın.', 'revenue-leak-detector'),
            __('Checkout öncesi dikkat dağıtan link ve mesajları azaltın.', 'revenue-leak-detector'),
            __('Kargo, ücret ve toplam tutarı daha erken net gösterin.', 'revenue-leak-detector'),
        );
    }

    if (strpos($title, 'Refund') !== false) {
        return array(
            __('İade nedenlerini gruplayıp en sık tekrar eden sorunu bulun.', 'revenue-leak-detector'),
            __('Ürün vaadini checkout mesajlarıyla hizalayın.', 'revenue-leak-detector'),
        );
    }

    if (strpos($title, 'Failure') !== false || strpos($title, 'Fail') !== false) {
        return array(
            __('Ödeme sağlayıcısı hata loglarını hemen kontrol edin.', 'revenue-leak-detector'),
            __('En sık başarısız sipariş nedenini çözüp tekrar deneyin.', 'revenue-leak-detector'),
        );
    }

    return array(
        __('En büyük kaçağın görüldüğü adımı bu hafta önceliklendirin.', 'revenue-leak-detector'),
        __('Değişiklikten sonra funnel oranlarını tekrar karşılaştırın.', 'revenue-leak-detector'),
    );
}

/**
 * Renders local dashboard header and date filters.
 *
 * @param array{start_date: string, end_date: string, preset: string} $filters    Date filters.
 * @param array<string, mixed>                        $local_data Local dashboard data.
 *
 * @return void
 */
function revenue_leak_detector_render_local_dashboard_header(array $filters, array $local_data)
{
    echo '<div class="rld-hero">';
    echo '<div>';
    echo '<h2>' . esc_html__('Revenue Leak Overview', 'revenue-leak-detector') . '</h2>';
    echo '<p>' . esc_html__('See where shoppers leak out of the WooCommerce funnel, what matters most right now, and what to fix next.', 'revenue-leak-detector') . '</p>';
    echo '</div>';
    echo '<div class="rld-hero-meta">';
    echo '<span class="rld-hero-pill">' . esc_html($filters['start_date'] . ' - ' . $filters['end_date']) . '</span>';
    revenue_leak_detector_render_date_presets($filters);
    echo '<form method="get" class="rld-filterbar">';
    echo '<input type="hidden" name="page" value="revenue-leak-detector" />';
    echo '<input type="hidden" name="tab" value="dashboard" />';
    echo '<input type="hidden" name="preset" value="custom" />';
    echo '<div class="rld-field">';
    echo '<label for="rld-start-date">' . esc_html__('Start Date', 'revenue-leak-detector') . '</label>';
    echo '<input type="date" id="rld-start-date" name="start_date" value="' . esc_attr($filters['start_date']) . '" />';
    echo '</div>';
    echo '<div class="rld-field">';
    echo '<label for="rld-end-date">' . esc_html__('End Date', 'revenue-leak-detector') . '</label>';
    echo '<input type="date" id="rld-end-date" name="end_date" value="' . esc_attr($filters['end_date']) . '" />';
    echo '</div>';
    echo '<div class="rld-filter-actions">';
    submit_button(__('Apply Filter', 'revenue-leak-detector'), 'primary', '', false);
    echo '<a class="button button-secondary" href="' . esc_url(add_query_arg(array('page' => 'revenue-leak-detector'), admin_url('admin.php'))) . '">' . esc_html__('Reset', 'revenue-leak-detector') . '</a>';
    echo '</div>';
    echo '</form>';
    echo '</div>';
    echo '</div>';
}

/**
 * Renders KPI cards for the local dashboard.
 *
 * @param array<string, mixed> $local_data Local dashboard payload.
 *
 * @return void
 */
function revenue_leak_detector_render_local_kpi_cards(array $local_data)
{
    $summary = $local_data['summary'];
    $top_issue = $local_data['top_issue'];
    $cards = array(
        array(
            'label'  => __('Revenue Leak Score', 'revenue-leak-detector'),
            'value'  => (int) $summary['leak_score'],
            'subtle' => __('Higher is healthier. Score blends abandonment, failures, and refunds.', 'revenue-leak-detector'),
            'tooltip' => revenue_leak_detector_get_leak_score_tooltip(),
        ),
        array(
            'label'  => __('Biggest User Loss', 'revenue-leak-detector'),
            'value'  => '<div class="rld-kpi-stack"><span class="rld-kpi-stack-top">' . esc_html__('Strongest Leak in Funnel', 'revenue-leak-detector') . '</span><span class="rld-kpi-stack-main">' . esc_html($summary['primary_leak_label']) . '</span><span class="rld-kpi-stack-bottom">' . esc_html(sprintf(__('%1$d users lost (%2$s)', 'revenue-leak-detector'), (int) $summary['primary_leak_count'], $summary['primary_leak_rate_label'])) . '</span></div>',
            'subtle' => __('Main place where shoppers stop before paying.', 'revenue-leak-detector'),
            'class'  => 'rld-card-problem',
            'value_class' => 'rld-value-compact',
            'subtle_class' => 'rld-subtle-strong',
            'allow_html' => true,
            'tooltip' => __('Shows the step with the highest user loss in the selected period. It compares cart-to-checkout loss and checkout-to-purchase loss.', 'revenue-leak-detector'),
        ),
        array(
            'label'  => __('Cart to Purchase Rate', 'revenue-leak-detector'),
            'value'  => $summary['conversion_rate_label'],
            'subtle' => __('Purchases divided by add-to-cart sessions.', 'revenue-leak-detector'),
            'tooltip' => __('Overall funnel conversion. It compares successful purchases against add-to-cart sessions.', 'revenue-leak-detector'),
        ),
        array(
            'label'  => __('Top Issue', 'revenue-leak-detector'),
            'value'  => $top_issue['title'],
            'subtle' => $top_issue['action'],
            'tooltip' => __('The highest-priority issue detected from current funnel behavior, failures, and refunds.', 'revenue-leak-detector'),
        ),
    );

    echo '<div class="rld-grid">';

    foreach ($cards as $card) {
        $card_class = isset($card['class']) ? ' ' . $card['class'] : '';
        $value_class = isset($card['value_class']) ? ' ' . $card['value_class'] : '';
        $subtle_class = isset($card['subtle_class']) ? ' ' . $card['subtle_class'] : '';
        if (! empty($card['tooltip'])) {
            $card_class .= ' rld-card-has-tooltip';
        }
        echo '<div class="rld-card' . esc_attr($card_class) . '">';
        echo '<div class="rld-label">' . esc_html($card['label']);
        if (! empty($card['tooltip'])) {
            echo revenue_leak_detector_render_info_tooltip(__('How this metric works', 'revenue-leak-detector'), $card['tooltip']);
        }
        echo '</div>';
        echo '<div class="rld-value' . esc_attr($value_class) . '">' . (! empty($card['allow_html']) ? wp_kses_post((string) $card['value']) : esc_html((string) $card['value'])) . '</div>';
        echo '<div class="rld-subtle' . esc_attr($subtle_class) . '">' . esc_html($card['subtle']) . '</div>';
        echo '</div>';
    }

    echo '</div>';
}

/**
 * Renders the next recommended action block.
 *
 * @param array<string, mixed> $local_data Local dashboard payload.
 *
 * @return void
 */
function revenue_leak_detector_render_next_action_block(array $local_data)
{
    $top_issue = $local_data['top_issue'];
    $action_items = revenue_leak_detector_get_next_action_items($top_issue);

    echo '<div class="rld-next-action">';
    echo '<div>';
    echo '<div class="rld-next-action-label"><span class="rld-inline-icon">' . revenue_leak_detector_get_icon_svg('action', 'rld-icon-action rld-icon-lg') . esc_html__('Next Action', 'revenue-leak-detector') . '</span>' . revenue_leak_detector_render_info_tooltip(__('How this recommendation works', 'revenue-leak-detector'), __('This block turns the highest-priority issue into concrete next steps you can act on now.', 'revenue-leak-detector')) . '</div>';
    echo '<div class="rld-next-action-title">' . esc_html($top_issue['action']) . '</div>';
    echo '<div class="rld-next-action-summary">' . esc_html($top_issue['title']) . '. ' . esc_html($top_issue['explanation']) . '</div>';
    echo '<div class="rld-next-action-reason"><strong>' . esc_html__('Why now:', 'revenue-leak-detector') . '</strong> ' . esc_html($top_issue['impact']) . '</div>';
    echo '<ul class="rld-next-action-list">';
    foreach ($action_items as $item) {
        echo '<li>' . revenue_leak_detector_get_icon_svg('action', 'rld-icon-action') . '<span>' . esc_html($item) . '</span></li>';
    }
    echo '</ul>';
    echo '</div>';
    echo '<div class="rld-next-action-meta">';
    echo '<span class="rld-next-action-pill">' . esc_html(revenue_leak_detector_get_severity_label((string) $top_issue['severity'])) . '</span>';
    if ((int) $top_issue['lost_users'] > 0) {
        echo '<span class="rld-next-action-pill">' . esc_html(sprintf(__('%d lost users', 'revenue-leak-detector'), (int) $top_issue['lost_users'])) . '</span>';
        echo '<span class="rld-next-action-pill">' . esc_html(sprintf(__('Estimated loss: %d users', 'revenue-leak-detector'), (int) $top_issue['lost_users'])) . '</span>';
    }
    echo '</div>';
    echo '</div>';
}

/**
 * Renders local funnel metrics.
 *
 * @param array<string, int> $funnel Funnel counts keyed by event type.
 *
 * @return void
 */
function revenue_leak_detector_render_local_funnel_section(array $funnel)
{
    echo '<div class="rld-panel">';
    echo '<h2 class="rld-section-title">' . esc_html__('Core Funnel', 'revenue-leak-detector') . ' ' . revenue_leak_detector_render_info_tooltip(__('How to read this funnel', 'revenue-leak-detector'), __('Follow shoppers from add to cart to checkout and purchase. Red blocks show where users are being lost between steps.', 'revenue-leak-detector')) . '</h2>';
    echo '<div class="rld-funnel-flow">';

    $steps = array(
        array(
            'key'        => 'add_to_cart',
            'count'      => (int) $funnel['add_to_cart'],
            'conversion' => null,
            'dropoff'    => null,
        ),
        array(
            'key'        => 'begin_checkout',
            'count'      => (int) $funnel['begin_checkout'],
            'conversion' => (int) $funnel['add_to_cart'] > 0 ? ((int) $funnel['begin_checkout'] / max(1, (int) $funnel['add_to_cart'])) : 0,
            'dropoff'    => max(0, (int) $funnel['add_to_cart'] - (int) $funnel['begin_checkout']),
        ),
        array(
            'key'        => 'payment_success',
            'count'      => (int) $funnel['payment_success'],
            'conversion' => (int) $funnel['begin_checkout'] > 0 ? ((int) $funnel['payment_success'] / max(1, (int) $funnel['begin_checkout'])) : 0,
            'dropoff'    => max(0, (int) $funnel['begin_checkout'] - (int) $funnel['payment_success']),
        ),
    );

    echo '<div class="rld-funnel-step rld-funnel-step-primary">';
    echo '<div class="rld-step-label">' . revenue_leak_detector_get_icon_svg('cart') . esc_html(revenue_leak_detector_get_event_label($steps[0]['key'])) . revenue_leak_detector_render_info_tooltip(__('Add to Cart meaning', 'revenue-leak-detector'), __('Number of tracked add-to-cart events in the selected date range.', 'revenue-leak-detector')) . '</div>';
    echo '<div class="rld-step-count">' . esc_html((string) $steps[0]['count']) . '</div>';
    echo '<span class="rld-event-key">' . esc_html($steps[0]['key']) . '</span>';
    echo '<div class="rld-step-meta"><span>' . esc_html__('Entry point of the tracked funnel.', 'revenue-leak-detector') . '</span></div>';
    echo '</div>';

    echo '<div class="rld-funnel-connector">';
    echo '<div class="rld-funnel-arrow">→</div>';
    echo '<div class="rld-funnel-connector-card">';
    echo '<div class="rld-funnel-connector-heading"><div class="rld-funnel-connector-label">' . revenue_leak_detector_get_icon_svg('loss', 'rld-icon-loss rld-icon-lg') . esc_html__('Cart to Checkout', 'revenue-leak-detector') . revenue_leak_detector_render_info_tooltip(__('Cart to Checkout meaning', 'revenue-leak-detector'), __('Shows how many users moved from cart intent into checkout, and how many were lost before starting checkout.', 'revenue-leak-detector')) . '</div></div>';
    echo '<div class="rld-funnel-connector-loss">' . revenue_leak_detector_get_icon_svg('warning', 'rld-icon-loss rld-icon-lg') . esc_html(sprintf(__('%d users lost', 'revenue-leak-detector'), (int) $steps[1]['dropoff'])) . '</div>';
    echo '<div class="rld-funnel-connector-value">' . esc_html(revenue_leak_detector_format_percent(1 - (float) $steps[1]['conversion'])) . ' ' . esc_html__('did not reach checkout', 'revenue-leak-detector') . '</div>';
    echo '<div class="rld-funnel-connector-sub">' . esc_html(sprintf(__('Only %s continued to checkout.', 'revenue-leak-detector'), revenue_leak_detector_format_percent((float) $steps[1]['conversion']))) . '</div>';
    echo '</div>';
    echo '</div>';

    echo '<div class="rld-funnel-step rld-funnel-step-primary">';
    echo '<div class="rld-step-label">' . revenue_leak_detector_get_icon_svg('checkout') . esc_html(revenue_leak_detector_get_event_label($steps[1]['key'])) . revenue_leak_detector_render_info_tooltip(__('Checkout Started meaning', 'revenue-leak-detector'), __('Number of tracked sessions that reached checkout.', 'revenue-leak-detector')) . '</div>';
    echo '<div class="rld-step-count">' . esc_html((string) $steps[1]['count']) . '</div>';
    echo '<span class="rld-event-key">' . esc_html($steps[1]['key']) . '</span>';
    echo '<div class="rld-step-meta">';
    echo '<span>' . esc_html(sprintf(__('Conversion from previous: %s', 'revenue-leak-detector'), revenue_leak_detector_format_percent((float) $steps[1]['conversion']))) . '</span>';
    echo '<span>' . esc_html(sprintf(__('Drop-off from previous: %d', 'revenue-leak-detector'), (int) $steps[1]['dropoff'])) . '</span>';
    echo '<span class="rld-step-dropoff">' . revenue_leak_detector_get_icon_svg('loss', 'rld-icon-loss') . esc_html(sprintf(__('Lost %d users here', 'revenue-leak-detector'), (int) $steps[1]['dropoff'])) . '</span>';
    echo '</div>';
    echo '</div>';

    echo '<div class="rld-funnel-connector">';
    echo '<div class="rld-funnel-arrow">→</div>';
    echo '<div class="rld-funnel-connector-card ' . esc_attr(((int) $steps[2]['dropoff'] === 0) ? 'rld-funnel-connector-card-ok' : '') . '">';
    echo '<div class="rld-funnel-connector-heading"><div class="rld-funnel-connector-label">' . revenue_leak_detector_get_icon_svg(((int) $steps[2]['dropoff'] === 0) ? 'success' : 'loss', ((int) $steps[2]['dropoff'] === 0) ? 'rld-icon-success rld-icon-lg' : 'rld-icon-loss rld-icon-lg') . esc_html__('Checkout to Purchase', 'revenue-leak-detector') . revenue_leak_detector_render_info_tooltip(__('Checkout to Purchase meaning', 'revenue-leak-detector'), __('Shows how many users who started checkout completed purchase, and how many dropped before payment success.', 'revenue-leak-detector')) . '</div></div>';
    if ((int) $steps[2]['dropoff'] === 0) {
        echo '<div class="rld-funnel-connector-loss">' . revenue_leak_detector_get_icon_svg('success', 'rld-icon-success rld-icon-lg') . esc_html__('0 users lost', 'revenue-leak-detector') . '</div>';
        echo '<div class="rld-funnel-connector-value">' . esc_html(revenue_leak_detector_format_percent((float) $steps[2]['conversion'])) . ' ' . esc_html__('completed purchase', 'revenue-leak-detector') . '</div>';
        echo '<div class="rld-funnel-connector-sub">' . esc_html__('Healthy progression from checkout to purchase.', 'revenue-leak-detector') . '</div>';
    } else {
        echo '<div class="rld-funnel-connector-loss">' . revenue_leak_detector_get_icon_svg('warning', 'rld-icon-loss rld-icon-lg') . esc_html(sprintf(__('%d users lost', 'revenue-leak-detector'), (int) $steps[2]['dropoff'])) . '</div>';
        echo '<div class="rld-funnel-connector-value">' . esc_html(revenue_leak_detector_format_percent(1 - (float) $steps[2]['conversion'])) . ' ' . esc_html__('did not complete purchase', 'revenue-leak-detector') . '</div>';
        echo '<div class="rld-funnel-connector-sub">' . esc_html(sprintf(__('Only %s completed purchase.', 'revenue-leak-detector'), revenue_leak_detector_format_percent((float) $steps[2]['conversion']))) . '</div>';
    }
    echo '</div>';
    echo '</div>';

    echo '<div class="rld-funnel-step rld-funnel-step-primary">';
    echo '<div class="rld-step-label">' . revenue_leak_detector_get_icon_svg('success', 'rld-icon-success') . esc_html(revenue_leak_detector_get_event_label($steps[2]['key'])) . revenue_leak_detector_render_info_tooltip(__('Purchase meaning', 'revenue-leak-detector'), __('Number of successful purchase events captured in the selected date range.', 'revenue-leak-detector')) . '</div>';
    echo '<div class="rld-step-count">' . esc_html((string) $steps[2]['count']) . '</div>';
    echo '<span class="rld-event-key">' . esc_html($steps[2]['key']) . '</span>';
    echo '<div class="rld-step-meta">';
    echo '<span>' . esc_html(sprintf(__('Conversion from previous: %s', 'revenue-leak-detector'), revenue_leak_detector_format_percent((float) $steps[2]['conversion']))) . '</span>';
    echo '<span>' . esc_html(sprintf(__('Drop-off from previous: %d', 'revenue-leak-detector'), (int) $steps[2]['dropoff'])) . '</span>';
    echo '<span class="rld-step-dropoff ' . esc_attr(((int) $steps[2]['dropoff'] === 0) ? 'rld-step-dropoff-ok' : '') . '">' . revenue_leak_detector_get_icon_svg(((int) $steps[2]['dropoff'] === 0) ? 'success' : 'loss', ((int) $steps[2]['dropoff'] === 0) ? 'rld-icon-success' : 'rld-icon-loss') . esc_html(((int) $steps[2]['dropoff'] === 0) ? __('No drop-off detected', 'revenue-leak-detector') : sprintf(__('Lost %d users here', 'revenue-leak-detector'), (int) $steps[2]['dropoff'])) . '</span>';
    echo '</div>';
    echo '</div>';

    echo '</div>';
    echo '</div>';
}

/**
 * Renders prioritized issue cards.
 *
 * @param array<int, array<string, mixed>> $issues Insight issues.
 *
 * @return void
 */
function revenue_leak_detector_render_local_issues_section(array $issues)
{
    echo '<div class="rld-panel">';
    echo '<h2 class="rld-section-title">' . esc_html__('What Needs Attention', 'revenue-leak-detector') . ' ' . revenue_leak_detector_render_info_tooltip(__('How issues are prioritized', 'revenue-leak-detector'), __('Issues are ranked by severity using funnel leakage, order failures, and refunds.', 'revenue-leak-detector')) . '</h2>';
    echo '<div class="rld-issues">';

    foreach ($issues as $issue) {
        $severity = (string) $issue['severity'];
        echo '<div class="rld-issue rld-issue-' . esc_attr($severity) . '">';
        $severity_icon = $severity === 'high' ? 'warning' : ($severity === 'medium' ? 'info' : 'success');
        $severity_icon_class = $severity === 'high' ? 'rld-icon-loss rld-icon-lg' : ($severity === 'medium' ? 'rld-icon-warning' : 'rld-icon-success');
        echo '<span class="rld-severity rld-severity-' . esc_attr($severity) . '">' . revenue_leak_detector_get_icon_svg($severity_icon, $severity_icon_class) . esc_html(revenue_leak_detector_get_severity_label($severity)) . '</span>';
        echo '<h3>' . esc_html($issue['title']) . '</h3>';
        echo '<p>' . esc_html($issue['explanation']) . '</p>';
        echo '<div class="rld-issue-impact">' . esc_html($issue['impact']) . '</div>';
        if ((int) $issue['lost_users'] > 0) {
            echo '<div class="rld-issue-lost">' . revenue_leak_detector_get_icon_svg('warning', 'rld-icon-loss') . esc_html(sprintf(__('Estimated loss: %d users', 'revenue-leak-detector'), (int) $issue['lost_users'])) . '</div>';
        }
        echo '<div class="rld-issue-action"><strong>' . esc_html__('Suggested action:', 'revenue-leak-detector') . '</strong> ' . esc_html($issue['action']) . '</div>';
        echo '</div>';
    }

    echo '</div>';
    echo '</div>';
}

/**
 * Renders the trend chart for add to cart and purchase events.
 *
 * @param array<int, array<string, int|string>> $trend Trend rows.
 *
 * @return void
 */
function revenue_leak_detector_render_local_trend_section(array $trend)
{
    $max_value = 1;
    $cart_points = array();
    $purchase_points = array();
    $labels = array();
    $total_carts = 0;
    $total_purchases = 0;
    $latest_day = $trend !== array() ? $trend[count($trend) - 1] : array(
        'add_to_cart' => 0,
        'payment_success' => 0,
    );
    $chart_width = 640;
    $chart_height = 220;
    $left = 24;
    $bottom = 26;
    $usable_width = $chart_width - ($left * 2);
    $usable_height = $chart_height - 40;
    $count = max(1, count($trend));

    foreach ($trend as $row) {
        $max_value = max($max_value, (int) $row['add_to_cart'], (int) $row['payment_success']);
        $total_carts += (int) $row['add_to_cart'];
        $total_purchases += (int) $row['payment_success'];
    }

    foreach ($trend as $index => $row) {
        $x = $left + (($usable_width / max(1, $count - 1)) * $index);
        $cart_y = 10 + ($usable_height - (($usable_height / $max_value) * (int) $row['add_to_cart']));
        $purchase_y = 10 + ($usable_height - (($usable_height / $max_value) * (int) $row['payment_success']));
        $cart_points[] = round($x, 1) . ',' . round($cart_y, 1);
        $purchase_points[] = round($x, 1) . ',' . round($purchase_y, 1);
        $labels[] = array(
            'x'     => $x,
            'label' => (string) $row['label'],
        );
    }

    echo '<div class="rld-panel rld-chart-card">';
    echo '<h2 class="rld-section-title">' . esc_html__('Last 7 Days Trend', 'revenue-leak-detector') . '</h2>';
    echo '<div class="rld-chart-wrap">';
    echo '<p class="rld-chart-summary">' . esc_html(sprintf(__('Last 7 day conversion: %s. Purchases are compared against add-to-cart intent.', 'revenue-leak-detector'), revenue_leak_detector_format_percent($total_carts > 0 ? ($total_purchases / $total_carts) : 0))) . '</p>';
    echo '<div class="rld-trend-metrics">';
    echo '<span class="rld-chip">' . esc_html__('7-Day Add to Cart', 'revenue-leak-detector') . ' <strong>' . esc_html((string) $total_carts) . '</strong></span>';
    echo '<span class="rld-chip">' . esc_html__('7-Day Purchases', 'revenue-leak-detector') . ' <strong>' . esc_html((string) $total_purchases) . '</strong></span>';
    echo '<span class="rld-chip">' . esc_html__('7-Day Conversion', 'revenue-leak-detector') . ' <strong>' . esc_html(revenue_leak_detector_format_percent($total_carts > 0 ? ($total_purchases / $total_carts) : 0)) . '</strong></span>';
    echo '<span class="rld-chip">' . esc_html__('Latest Day Conversion', 'revenue-leak-detector') . ' <strong>' . esc_html(revenue_leak_detector_format_percent((int) $latest_day['add_to_cart'] > 0 ? (((int) $latest_day['payment_success']) / ((int) $latest_day['add_to_cart'])) : 0)) . '</strong></span>';
    echo '</div>';
    echo '<div class="rld-chart-legend">';
    echo '<span class="rld-chart-key"><span class="rld-chart-dot" style="background:#0ea5e9;"></span>' . esc_html__('Add to Cart', 'revenue-leak-detector') . '</span>';
    echo '<span class="rld-chart-key"><span class="rld-chart-dot" style="background:#22c55e;"></span>' . esc_html__('Purchase', 'revenue-leak-detector') . '</span>';
    echo '</div>';
    echo '<svg viewBox="0 0 ' . esc_attr((string) $chart_width) . ' ' . esc_attr((string) $chart_height) . '" width="100%" height="220" role="img" aria-label="' . esc_attr__('Trend chart', 'revenue-leak-detector') . '">';
    echo '<line x1="' . esc_attr((string) $left) . '" y1="' . esc_attr((string) ($chart_height - $bottom)) . '" x2="' . esc_attr((string) ($chart_width - $left)) . '" y2="' . esc_attr((string) ($chart_height - $bottom)) . '" stroke="#cbd5e1" stroke-width="1" />';
    echo '<polyline class="rld-chart-line-cart" points="' . esc_attr(implode(' ', $cart_points)) . '"></polyline>';
    echo '<polyline class="rld-chart-line-purchase" points="' . esc_attr(implode(' ', $purchase_points)) . '"></polyline>';
    foreach ($labels as $label) {
        echo '<text class="rld-chart-axis" x="' . esc_attr((string) $label['x']) . '" y="' . esc_attr((string) ($chart_height - 6)) . '" text-anchor="middle">' . esc_html($label['label']) . '</text>';
    }
    echo '</svg>';
    echo '</div>';
    echo '</div>';
}

/**
 * Handles admin API base URL updates.
 *
 * @return void
 */
function revenue_leak_detector_handle_save_settings()
{
    if (! current_user_can('manage_options')) {
        wp_die(esc_html__('You are not allowed to perform this action.', 'revenue-leak-detector'));
    }

    check_admin_referer('revenue_leak_detector_save_settings');

    if (revenue_leak_detector_should_show_developer_settings() && isset($_POST['api_base_url'])) {
        $api_base_url = sanitize_text_field(wp_unslash($_POST['api_base_url']));
        update_option('revenue_leak_detector_api_base_url', untrailingslashit($api_base_url));
    }

    wp_safe_redirect(
        add_query_arg(
            array(
                'page' => 'revenue-leak-detector',
                'settings-updated' => '1',
            ),
            admin_url('admin.php')
        )
    );
    exit;
}

/**
 * Renders the plugin admin page.
 *
 * @return void
 */
function revenue_leak_detector_render_admin_page()
{
    if (! current_user_can('manage_options')) {
        return;
    }

    $active_tab = revenue_leak_detector_get_admin_tab();
    $filters = revenue_leak_detector_get_local_dashboard_filters();
    $local_dashboard_data = revenue_leak_detector_get_local_dashboard_data($filters);

    echo '<div class="wrap">';
    echo '<h1>' . esc_html__('Revenue Leak Detector', 'revenue-leak-detector') . '</h1>';
    echo '<p>' . esc_html__('Track funnel leakage, spot the biggest conversion problem, and see what to fix next.', 'revenue-leak-detector') . '</p>';
    revenue_leak_detector_render_action_notices();
    revenue_leak_detector_render_local_dashboard_styles();
    revenue_leak_detector_render_admin_tabs($active_tab);

    if ($active_tab === 'settings') {
        echo '<div class="postbox" style="padding:16px; margin-top:16px;">';
        echo '<h2 style="margin-top:0;">' . esc_html__('Plugin Configuration', 'revenue-leak-detector') . '</h2>';
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
        wp_nonce_field('revenue_leak_detector_save_settings');
        echo '<input type="hidden" name="action" value="revenue_leak_detector_save_settings" />';
        echo '<table class="form-table" role="presentation"><tbody>';
        if (revenue_leak_detector_should_show_developer_settings()) {
            echo '<tr>';
            echo '<th scope="row"><label for="revenue-leak-detector-api-base-url">' . esc_html__('API Base URL', 'revenue-leak-detector') . '</label></th>';
            echo '<td><input type="url" class="regular-text" id="revenue-leak-detector-api-base-url" name="api_base_url" value="' . esc_attr(revenue_leak_detector_get_api_base_url()) . '" placeholder="https://api.example.com" /><p class="description">' . esc_html__('Developer-only setting for custom backend integrations.', 'revenue-leak-detector') . '</p></td>';
            echo '</tr>';
        }
        echo '</tbody></table>';
        submit_button(__('Save Settings', 'revenue-leak-detector'));
        echo '</form>';
        echo '</div>';
    }

    if ($active_tab === 'dashboard') {
        echo '<div class="rld-shell">';
        revenue_leak_detector_render_local_dashboard_header($filters, $local_dashboard_data);
        revenue_leak_detector_render_local_kpi_cards($local_dashboard_data);
        echo '<div class="rld-summary-grid">';
        revenue_leak_detector_render_local_funnel_section($local_dashboard_data['funnel']);
        echo '<div class="rld-side-stack">';
        revenue_leak_detector_render_next_action_block($local_dashboard_data);
        revenue_leak_detector_render_local_issues_section($local_dashboard_data['issues']);
        echo '</div>';
        echo '</div>';
        revenue_leak_detector_render_local_trend_section($local_dashboard_data['trend']);
        echo '</div>';
    }

    echo '</div>';
}

/**
 * Plugin activation callback.
 *
 * @return void
 */
function revenue_leak_detector_activate()
{
    revenue_leak_detector_create_queue_table();
    revenue_leak_detector_schedule_cron();
}

/**
 * Plugin deactivation callback.
 *
 *
 * @return void
 */
function revenue_leak_detector_deactivate()
{
    revenue_leak_detector_clear_cron();
}

register_activation_hook(__FILE__, 'revenue_leak_detector_activate');
register_deactivation_hook(__FILE__, 'revenue_leak_detector_deactivate');
add_action('init', 'revenue_leak_detector_load_textdomain');
add_action('init', 'revenue_leak_detector_schedule_cron');
add_action('admin_menu', 'revenue_leak_detector_register_admin_menu');
add_action('admin_post_revenue_leak_detector_save_settings', 'revenue_leak_detector_handle_save_settings');
add_action(REVENUE_LEAK_DETECTOR_CRON_HOOK, 'revenue_leak_detector_run_scheduled_batch_send');
add_action('woocommerce_add_to_cart', 'revenue_leak_detector_capture_add_to_cart', 10, 3);
add_action('template_redirect', 'revenue_leak_detector_capture_view_cart');
add_action('woocommerce_cart_item_removed', 'revenue_leak_detector_capture_remove_from_cart', 10, 2);
add_action('woocommerce_add_to_cart', 'revenue_leak_detector_reset_begin_checkout_marker', 20);
add_action('woocommerce_cart_item_removed', 'revenue_leak_detector_reset_begin_checkout_marker');
add_action('woocommerce_after_cart_item_quantity_update', 'revenue_leak_detector_reset_begin_checkout_marker');
add_action('woocommerce_cart_emptied', 'revenue_leak_detector_reset_begin_checkout_marker');
add_action('template_redirect', 'revenue_leak_detector_capture_begin_checkout');
add_action('woocommerce_before_checkout_form', 'revenue_leak_detector_capture_begin_checkout_from_checkout_form');
add_action('woocommerce_checkout_order_processed', 'revenue_leak_detector_capture_checkout_info_events', 10, 3);
add_action('template_redirect', 'revenue_leak_detector_capture_payment_success_from_request');
add_action('woocommerce_thankyou', 'revenue_leak_detector_capture_payment_success');
add_action('woocommerce_payment_complete', 'revenue_leak_detector_capture_payment_success');
add_action('woocommerce_order_status_processing', 'revenue_leak_detector_capture_payment_success');
add_action('woocommerce_order_status_completed', 'revenue_leak_detector_capture_payment_success');
add_action('woocommerce_order_status_failed', 'revenue_leak_detector_capture_order_failed');
add_action('woocommerce_order_status_cancelled', 'revenue_leak_detector_capture_order_cancelled');
add_action('woocommerce_order_refunded', 'revenue_leak_detector_capture_refund', 10, 2);
