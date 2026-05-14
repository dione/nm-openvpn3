#include <glib.h>
#include <string.h>
#include "ovpn3-routes.h"

static void
test_parse_two_routes (void)
{
	const gchar *table =
		"Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
		"tun0\t00E01BAC\t00000000\t0001\t0\t0\t50\t00F0FFFF\t0\t0\t0\n"
		"tun0\t0001010A\t01401FAC\t0003\t0\t0\t0\t0000FFFF\t0\t0\t0\n"
		"wlp0s20f3\t0000FEA9\t00000000\t0001\t0\t0\t300\t0000FFFF\t0\t0\t0\n";

	GArray *routes = ovpn3_parse_proc_routes (table, "tun0");
	g_assert_nonnull (routes);
	g_assert_cmpuint (routes->len, ==, 2);

	/* On a little-endian host, /proc/net/route hex "00E01BAC" matches the
	 * value of inet_addr("172.27.224.0") — sin_addr.s_addr style.  Parser
	 * returns it verbatim (no byte swap), and that is what NM expects in
	 * NM_VPN_PLUGIN_IP4_CONFIG_ADDRESS / ROUTES.  */
	Ovpn3Route r0 = g_array_index (routes, Ovpn3Route, 0);
	g_assert_cmphex (r0.dest_be, ==, 0x00E01BAC);     /* 172.27.224.0 */
	g_assert_cmpuint (r0.prefix, ==, 20);             /* mask 00F0FFFF popcount */
	g_assert_cmphex (r0.next_hop_be, ==, 0);
	g_assert_cmpuint (r0.metric, ==, 50);

	Ovpn3Route r1 = g_array_index (routes, Ovpn3Route, 1);
	g_assert_cmphex (r1.dest_be, ==, 0x0001010A);     /* 10.1.1.0 */
	g_assert_cmpuint (r1.prefix, ==, 16);
	g_assert_cmphex (r1.next_hop_be, ==, 0x01401FAC); /* 172.31.64.1 */
	g_assert_cmpuint (r1.metric, ==, 0);

	g_array_free (routes, TRUE);
}

static void
test_iface_filter (void)
{
	const gchar *table =
		"Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
		"tun0\t00E01BAC\t00000000\t0001\t0\t0\t50\t0000F0FF\t0\t0\t0\n"
		"wlp0s20f3\t00E01BAC\t00000000\t0001\t0\t0\t60\t0000F0FF\t0\t0\t0\n";

	GArray *routes = ovpn3_parse_proc_routes (table, "wlp0s20f3");
	g_assert_cmpuint (routes->len, ==, 1);
	Ovpn3Route r = g_array_index (routes, Ovpn3Route, 0);
	g_assert_cmpuint (r.metric, ==, 60);
	g_array_free (routes, TRUE);
}

static void
test_empty_table_returns_empty_array (void)
{
	const gchar *table =
		"Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n";

	GArray *routes = ovpn3_parse_proc_routes (table, "tun0");
	g_assert_nonnull (routes);
	g_assert_cmpuint (routes->len, ==, 0);
	g_array_free (routes, TRUE);
}

int main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);
	g_test_add_func ("/ovpn3/routes/parse-two", test_parse_two_routes);
	g_test_add_func ("/ovpn3/routes/iface-filter", test_iface_filter);
	g_test_add_func ("/ovpn3/routes/empty", test_empty_table_returns_empty_array);
	return g_test_run ();
}
