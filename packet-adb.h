/*
 * packet-adb.h
 *
 * Definitions for Android Debug Bridge (ADB) protocol dissection
 * Author: Geir Sporsheim <geir.sporsheim@gmail.com>
 */

#ifndef PACKET_ADB_H_
#define PACKET_ADB_H_

#define TCP_PORT_ADB 5555

#define A_SYNC 0x434e5953
#define A_CNXN 0x4e584e43
#define A_OPEN 0x4e45504f
#define A_OKAY 0x59414b4f
#define A_CLSE 0x45534c43
#define A_WRTE 0x45545257

#endif /* PACKET_ADB_H_ */
