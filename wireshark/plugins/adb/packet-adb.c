/*
 * packet-adb.c
 *
 * Routines for Android Debug Bridge (ADB) protocol dissection
 * Author: Geir Sporsheim <geir.sporsheim@gmail.com>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <epan/packet.h>
#include <epan/dissectors/packet-tcp.h>
#include "packet-adb.h"

static int proto_adb = -1;
static int hf_adb_pdu_command = -1;
static int hf_adb_pdu_arg0 = -1;
static int hf_adb_pdu_arg1 = -1;
static int hf_adb_pdu_length = -1;
static int hf_adb_pdu_crc32 = -1;
static int hf_adb_pdu_magic = -1;
static gint ett_adb = -1;

static const value_string map_adb_commands[] = {
    { A_SYNC, "SYNC" },
    { A_CNXN, "CONNECT" },
    { A_OPEN, "OPEN" },
    { A_OKAY, "READY" },
    { A_CLSE, "CLOSE" },
    { A_WRTE, "WRITE" }
};

static void dissect_adb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, FRAME_HEADER_LEN,
                     get_adb_message_len, dissect_adb_message);
}

static void dissect_adb_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    guint32 command_identifier = tvb_get_letohl(tvb, 0);

    const gchar *str = match_strval(command_identifier, map_adb_commands);
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ADB");
	col_add_fstr(pinfo->cinfo, COL_INFO, "%s", str);

	if (tree) {
		proto_item *ti = NULL;
		proto_tree *adb_tree = NULL;

		ti = proto_tree_add_item(tree, proto_adb, tvb, 0, -1, ENC_NA);
		adb_tree = proto_item_add_subtree(ti, ett_adb);
		proto_tree_add_item(adb_tree, hf_adb_pdu_command, tvb, 0, 4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(adb_tree, hf_adb_pdu_arg0, tvb, 4, 4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(adb_tree, hf_adb_pdu_arg1, tvb, 8, 4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(adb_tree, hf_adb_pdu_length, tvb, 12, 4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(adb_tree, hf_adb_pdu_crc32, tvb, 16, 4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(adb_tree, hf_adb_pdu_magic, tvb, 20, 4, ENC_LITTLE_ENDIAN);
	}
}

static guint get_adb_message_len(packet_info *pinfo, tvbuff_t *tvb, int offset) {
    return (guint)tvb_get_letohl(tvb, offset + 12) + FRAME_HEADER_LEN;
}

void proto_register_adb(void) {
	static hf_register_info hf[] = {
		{ &hf_adb_pdu_command,
			{ "Command Identifier", "adb.command",
				FT_UINT32, BASE_DEC,
				VALS(map_adb_commands), 0x0,
				"ADB Command Identifier", HFILL
			}
		},

		{ &hf_adb_pdu_arg0,
			{ "arg0", "adb.arg0",
				FT_UINT32, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL
			}
		},

		{ &hf_adb_pdu_arg1,
			{ "arg1", "adb.arg1",
				FT_UINT32, BASE_DEC,
				NULL, 0x0,
				NULL, HFILL
			}
		},

		{ &hf_adb_pdu_length,
			{ "Data Length", "adb.length",
				FT_UINT32, BASE_DEC,
				NULL, 0x0,
				"ADB Data Length", HFILL
			}
		},

		{ &hf_adb_pdu_crc32,
			{ "crc32", "adb.crc32",
				FT_UINT32, BASE_DEC,
				NULL, 0x0,
				"ADB Payload Checksum", HFILL
			}
		},

		{ &hf_adb_pdu_magic,
			{ "magic", "adb.magic",
				FT_UINT32, BASE_DEC,
				NULL, 0x0,
				"ADB Magic", HFILL
			}
		}
	};

	static gint *ett[] = {
        &ett_adb
    };

	proto_adb = proto_register_protocol(
			"Android Debug Bridge Protocol",
			"ADB",
			"adb");

    proto_register_field_array(proto_adb, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_adb(void) {
	static dissector_handle_t adb_handle;

	adb_handle = create_dissector_handle(dissect_adb, proto_adb);
	dissector_add_uint("tcp.port", TCP_PORT_ADB, adb_handle);
}
