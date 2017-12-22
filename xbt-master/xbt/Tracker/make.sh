g++ $@ -DEPOLL -DNDEBUG -I ../misc -I . -O3 -o xbt_tracker -std=c++11 \
	../misc/bt_misc.cpp \
	../misc/database.cpp \
	../misc/sha1.cpp \
	../misc/socket.cpp \
	../misc/sql_query.cpp \
	../misc/xcc_z.cpp \
	config.cpp \
	connection.cpp \
	epoll.cpp \
	server.cpp \
	tracker_input.cpp \
	transaction.cpp \
	"XBT Tracker.cpp" \
	`mysql_config --libs` -lz && strip xbt_tracker
