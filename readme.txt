=== Revenue Leak Detector ===
Contributors: growthhooks
Donate link: https://ugur.me
Tags: woocommerce, checkout, cart abandonment, conversion optimization, analytics
Requires at least: 6.4
Tested up to: 6.9
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Find checkout leaks, cart abandonment points, and the next action to recover WooCommerce conversions.

Homepage: https://ugur.me

== Description ==

Revenue Leak Detector shows where revenue is slipping away between add to cart, checkout, and purchase.

The plugin stores funnel events locally in your WordPress database and does not send store, customer, order, or analytics data to an external service.

Instead of raw analytics, it gives you a focused conversion view:

* where the biggest user loss is happening
* which issue needs attention first
* what action to take next

It is built for store owners who want faster answers without digging through complex reports.

= What You Get =

* Track the core WooCommerce funnel from cart to purchase
* Score funnel health with a simple Revenue Leak Score
* Spot the biggest conversion loss in seconds
* Prioritize the most urgent issue automatically
* Get a practical next-step recommendation
* Review 7-day conversion trends at a glance
* Filter by date range with quick presets

= Free v1 Focus =

This version is intentionally focused. It gives you the essential funnel diagnostics you need to spot leaks quickly and act on them.

== Installation ==

1. Upload the plugin files to the `/wp-content/plugins/revenue-leak-detector` directory, or install the plugin through the WordPress plugins screen.
2. Activate the plugin through the `Plugins` screen in WordPress.
3. Make sure WooCommerce is active.
4. Open `Revenue Leak Detector` from the WordPress admin menu.

== Frequently Asked Questions ==

= Does this require WooCommerce? =

Yes. Revenue Leak Detector is built for WooCommerce stores.

= Does it send data anywhere? =

No. Revenue Leak Detector stores captured WooCommerce funnel events in a local WordPress database table and builds the dashboard from that local data.

= What data does it store? =

The plugin stores WooCommerce funnel event details such as event type, event time, product/cart/order totals, item counts, product details, payment or shipping method labels, and order status where relevant. It does not store billing address, shipping address, email address, phone number, IP address, user agent, referrer URL, full request URL, WordPress user ID, WooCommerce session ID, order ID, refund ID, or cart hash in event payloads.

= Can I filter by date? =

Yes. You can use preset ranges or choose a custom start and end date.

== Screenshots ==

1. Conversion dashboard with leak score, top issue, and next action

== Changelog ==

= 1.0.0 =

* First public free release
* Added WooCommerce funnel tracking and conversion dashboard
* Added Revenue Leak Score, issue prioritization, and next action guidance
* Added date filtering and 7-day trend visibility
* Added local-only data handling for the WordPress.org release
